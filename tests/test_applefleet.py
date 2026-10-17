import csv
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.parse
from datetime import timedelta
from pathlib import Path

from applefleet import cli, simulate
from applefleet.checks import CRITICAL, FIX, INFO, WARNING, Config, device_actions, load_vip, run_all
from applefleet.jamf import JamfClient, export, normalise_computer
from applefleet.model import from_dict, load, version_tuple

NOW = simulate.DEMO_NOW
FIXTURES = Path(__file__).parent / "fixtures"


def ts(**delta):
    return (NOW + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mac(name="Mac", **over):
    d = {"id": name, "name": name, "serial": "S-" + name, "platform": "macOS", "model": "MacBook Air (M2)",
         "osVersion": "26.0.1", "managed": True, "supervised": True, "enrolledViaAde": True, "userApprovedMdm": True,
         "appleSilicon": True, "lastContact": ts(hours=-3), "lastInventory": ts(hours=-20), "username": "u." + name,
         "realName": name, "fileVaultEnabled": True, "recoveryKeyEscrowed": True, "sipEnabled": True,
         "gatekeeperEnabled": True, "firewallEnabled": True, "bootstrapTokenEscrowed": True,
         "storageTotalMb": 100000, "storageFreeMb": 50000, "warrantyEnds": "2028-01-01"}
    d.update(over)
    return d


def phone(name="Phone", platform="iOS", **over):
    d = {"id": name, "name": name, "serial": "S-" + name, "platform": platform, "model": "iPhone 16",
         "osVersion": "26.0.1", "managed": True, "supervised": True, "enrolledViaAde": True,
         "lastInventory": ts(hours=-5), "username": "u." + name, "passcodePresent": True,
         "storageTotalMb": 100000, "storageFreeMb": 40000, "warrantyEnds": "2028-01-01"}
    d.update(over)
    return d


def inv(devices=(), apns=200, ade=200, vpp=200, ade_devices=(), extra_ade=()):
    return from_dict({"collectedAt": ts(), "organisation": "t", "devices": list(devices),
                      "apnsCertificate": {"expires": ts(days=apns)} if apns is not None else None,
                      "adeInstances": [{"name": "ABM", "serverUuid": "U1", "tokenExpires": ts(days=ade)}, *extra_ade],
                      "vppLocations": [{"name": "VPP", "locationName": "L1", "tokenExpires": ts(days=vpp)}],
                      "adeDevices": list(ade_devices)})


def found(i, c=None):
    return [(f.code, f.severity, f.device) for f in run_all(i, c)]


class Clean(unittest.TestCase):
    def test_healthy_fleet_has_no_findings(self):
        self.assertEqual(found(inv([mac(), phone(), phone("Pad", "iPadOS", model="iPad Air")],
                                   ade_devices=[{"serial": "S-Mac"}, {"serial": "S-Phone"}])), [])


class PlatformTokens(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(found(inv(apns=31)), [])
        self.assertEqual(found(inv(apns=30)), [("apns_expiring", WARNING, "Jamf Pro")])
        self.assertEqual(found(inv(apns=14)), [("apns_expiring", CRITICAL, "Jamf Pro")])
        r = run_all(inv(vpp=-3, ade=20))
        self.assertEqual([(f.code, f.severity) for f in r], [("token_expiring", CRITICAL), ("token_expiring", WARNING)])
        self.assertIn("expired 3 days ago", r[0].detail)
        self.assertEqual(found(inv(apns=None)), [])            # no APNs date: shown as 'not provided', not guessed

    def test_renewed_token_and_apns_override(self):
        renewed = inv(ade=5, extra_ade=[{"name": "ABM (new)", "serverUuid": "U1", "tokenExpires": ts(days=360)}])
        self.assertEqual(found(renewed), [])                   # same ABM server, newer token carries the service
        other = inv(ade=5, extra_ade=[{"name": "Other", "serverUuid": "U2", "tokenExpires": ts(days=360)}])
        self.assertEqual(found(other), [("token_expiring", CRITICAL, "Jamf Pro")])
        i = from_dict({"collectedAt": ts(), "apnsCertificate": {"expires": ts(days=5)}}, apns_override="2027-10-01")
        self.assertEqual(found(i), [])                         # renewed after the export: the argument wins


class OsCurrency(unittest.TestCase):
    def test_version_comparison(self):
        self.assertGreater(version_tuple("14.10"), version_tuple("14.9"))
        self.assertGreater(version_tuple("17.7.2"), version_tuple("17.7"))
        self.assertEqual(version_tuple("17.7"), version_tuple("17.7.0"))
        self.assertEqual(version_tuple("26.0.1 (a)"), (26, 0, 1))
        self.assertGreater(version_tuple("26.0"), version_tuple("15.7.1"))

    def test_minimum_and_unsupported_major(self):
        c = Config(minimum={"macOS": "15.7", "iOS": "18.7", "iPadOS": "18.7"})
        r = found(inv([mac("A", osVersion="15.6.1"), mac("B", osVersion="13.7.8"), mac("C", osVersion="15.10"),
                       phone("P", osVersion="17.7.2"), phone("Q", osVersion="16.7.10")]), c)
        self.assertIn(("os_below_minimum", WARNING, "A"), r)
        self.assertIn(("os_unsupported", CRITICAL, "B"), r)
        self.assertNotIn("C", [d for _, _, d in r])            # 15.10 is above 15.7
        self.assertIn(("os_below_minimum", WARNING, "P"), r)
        self.assertEqual([x for x in r if x[2] == "Q"], [("os_unsupported", CRITICAL, "Q")])   # not reported twice


class MacSecurity(unittest.TestCase):
    def test_filevault(self):
        r = found(inv([mac("Off", fileVaultEnabled=False, recoveryKeyEscrowed=False),
                       mac("NoKey", recoveryKeyEscrowed=False)]))
        self.assertEqual(r, [("filevault_off", CRITICAL, "Off"), ("filevault_key_not_escrowed", WARNING, "NoKey")])

    def test_sip_gatekeeper_firewall(self):
        r = found(inv([mac(sipEnabled=False, gatekeeperEnabled=False, firewallEnabled=False)]))
        self.assertEqual(sorted(r), [("firewall_off", WARNING, "Mac"), ("gatekeeper_off", WARNING, "Mac"),
                                     ("sip_disabled", CRITICAL, "Mac")])

    def test_bootstrap_only_on_apple_silicon_and_mdm_approval(self):
        r = found(inv([mac("Arm", bootstrapTokenEscrowed=False),
                       mac("Intel", appleSilicon=False, bootstrapTokenEscrowed=False),
                       mac("Manual", supervised=False, userApprovedMdm=False)]))
        self.assertEqual(sorted(r), [("bootstrap_token_missing", WARNING, "Arm"),
                                     ("mdm_not_user_approved", WARNING, "Manual")])

    def test_not_collected_values_are_skipped(self):
        nulls = {k: None for k in ("supervised", "userApprovedMdm", "fileVaultEnabled", "recoveryKeyEscrowed",
                                   "sipEnabled", "gatekeeperEnabled", "firewallEnabled", "bootstrapTokenEscrowed",
                                   "storageFreeMb", "warrantyEnds")}
        self.assertEqual(found(inv([mac(**nulls)])), [])


class MobileSecurity(unittest.TestCase):
    def test_passcode_supervision_ade(self):
        r = found(inv([phone("NoCode", passcodePresent=False),
                       phone("Pad", "iPadOS", supervised=False, enrolledViaAde=False)]))
        self.assertEqual(sorted(r), [("no_passcode", CRITICAL, "NoCode"), ("not_ade_enrolled", WARNING, "Pad"),
                                     ("not_supervised", WARNING, "Pad")])


class EnrollmentAndHardware(unittest.TestCase):
    def test_checkin_thresholds_and_unmanaged(self):
        r = found(inv([mac("A", lastContact=ts(days=-13), lastInventory=ts(days=-13)),
                       phone("B", lastInventory=ts(days=-15)), phone("C", lastInventory=ts(days=-46)),
                       mac("D", managed=False, lastContact=ts(days=-200), fileVaultEnabled=False)]))
        self.assertEqual(r, [("checkin_stale", CRITICAL, "C"), ("checkin_stale", WARNING, "B"),
                             ("unmanaged_record", INFO, "D")])     # unmanaged: only the clean-up note

    def test_abm_assigned_never_enrolled(self):
        r = run_all(inv([mac()], ade_devices=[{"serial": "s-mac", "profileStatus": "PUSHED"},
                                               {"serial": "NEW1", "model": "iPad Air", "profileStatus": "EMPTY"}]))
        self.assertEqual([(f.code, f.device) for f in r], [("abm_never_enrolled", "NEW1")])
        self.assertIn("No PreStage", r[0].detail)

    def test_storage_and_warranty(self):
        r = found(inv([mac("A", storageFreeMb=11000), mac("B", storageFreeMb=9000), mac("C", storageFreeMb=4000),
                       mac("W", warrantyEnds=ts(days=40)), mac("X", warrantyEnds=ts(days=-100)),
                       mac("Gone", warrantyEnds=ts(days=-100), lastContact=ts(days=-90), lastInventory=ts(days=-90))]))
        self.assertIn(("storage_low", CRITICAL, "C"), r)
        self.assertIn(("storage_low", WARNING, "B"), r)
        self.assertNotIn("A", [d for _, _, d in r])
        self.assertIn(("warranty_ending", WARNING, "W"), r)
        self.assertIn(("warranty_ended", INFO, "X"), r)
        self.assertNotIn(("warranty_ended", INFO, "Gone"), r)  # not in use any more: the check-in finding covers it


class Vip(unittest.TestCase):
    def test_vip_findings_go_up_one_level(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "vip.txt"
            p.write_text("# board\nE.Navarro  \n\n", encoding="utf-8")
            vip = load_vip(p)
        self.assertEqual(vip, {"e.navarro"})
        i = inv([mac("Exec", username="e.navarro", recoveryKeyEscrowed=False, firewallEnabled=False,
                     sipEnabled=False, warrantyEnds=ts(days=-30), osVersion="26.0.1"),
                 mac("Staff", recoveryKeyEscrowed=False)])
        r = run_all(i, Config(vip=vip))
        exec_sev = {f.code: f.severity for f in r if f.device == "Exec"}
        self.assertEqual(exec_sev, {"filevault_key_not_escrowed": CRITICAL, "firewall_off": CRITICAL,
                                    "sip_disabled": CRITICAL, "warranty_ended": WARNING})
        self.assertTrue(all(f.detail.endswith("(VIP)") and f.vip for f in r if f.device == "Exec"))
        self.assertEqual([f.severity for f in r if f.device == "Staff"], [WARNING])
        rows = device_actions(i, r)
        self.assertEqual([x["device"] for x in rows], ["Exec", "Staff"])   # one row per device, worst first
        self.assertEqual(rows[0]["count"], 4)


class FakeJamf:
    """Answers urllib requests from tests/fixtures; records what was asked."""

    def __init__(self, mobile_detail=True):
        self.calls = []
        self.mobile_detail = mobile_detail

    def __call__(self, req, timeout=None):
        url = urllib.parse.urlparse(req.full_url)
        q = urllib.parse.parse_qs(url.query)
        self.calls.append((req.get_method(), url.path, q, req.data))
        name = {"/api/oauth/token": None, "/api/v1/device-enrollments": "device_enrollments",
                "/api/v1/device-enrollments/1/devices": "device_enrollment_1_devices",
                "/api/v1/volume-purchasing-locations": "vpp_locations", "/api/v2/mobile-devices": "mobile_list",
                "/api/v2/mobile-devices/301/detail": "mobile_device_301_detail"}.get(url.path, "")
        if url.path == "/api/oauth/token":
            body = {"access_token": "t0k", "expires_in": 300}
        elif url.path == "/api/v1/computers-inventory":
            body = json.loads((FIXTURES / f"computers_page{q['page'][0]}.json").read_text())
        elif url.path == "/api/v2/mobile-devices/detail":
            if not self.mobile_detail:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            body = json.loads((FIXTURES / "mobile_detail_page0.json").read_text())
        else:
            body = json.loads((FIXTURES / f"{name}.json").read_text())
        return io.BytesIO(json.dumps(body).encode())


class Exporter(unittest.TestCase):
    def test_paging_auth_and_normalisation(self):
        fake = FakeJamf()
        data = export(JamfClient("https://test.jamfcloud.com/", "cid", "s3cret", page_size=2, opener=fake),
                      "test", "2026-10-28", log=lambda *_: None)
        token_call = fake.calls[0]
        self.assertEqual(token_call[:2], ("POST", "/api/oauth/token"))
        self.assertEqual(urllib.parse.parse_qs(token_call[3].decode()),
                         {"client_id": ["cid"], "client_secret": ["s3cret"], "grant_type": ["client_credentials"]})
        self.assertFalse(any("s3cret" in path + json.dumps(q) for _, path, q, _ in fake.calls))
        comp = [c for c in fake.calls if c[1] == "/api/v1/computers-inventory"]
        self.assertEqual([c[2]["page"] for c in comp], [["0"], ["1"]])          # 3 records, page size 2
        self.assertIn("DISK_ENCRYPTION", comp[0][2]["section"])
        self.assertEqual(sum(1 for c in fake.calls if c[1] == "/api/oauth/token"), 1)   # token reused
        by = {d["serial"]: d for d in data["devices"]}
        self.assertEqual(len(by), 5)
        good, bad, unmanaged = by["TST0000001"], by["TST000000002"], by["TST0000003"]
        self.assertEqual((good["fileVaultEnabled"], good["recoveryKeyEscrowed"], good["bootstrapTokenEscrowed"],
                          good["appleSilicon"], good["storageFreeMb"]), (True, True, True, True, 312000))
        self.assertEqual((bad["fileVaultEnabled"], bad["sipEnabled"], bad["gatekeeperEnabled"], bad["appleSilicon"],
                          bad["bootstrapTokenEscrowed"], bad["storageTotalMb"]), (False, False, False, False, None, 500000))
        self.assertEqual((unmanaged["managed"], unmanaged["sipEnabled"], unmanaged["recoveryKeyEscrowed"]),
                         (False, None, False))
        self.assertEqual(normalise_computer({})["name"], "?")                     # empty record does not crash
        phone_, pad = by["TSTM000001"], by["TSTM000002"]
        self.assertEqual((phone_["platform"], phone_["passcodePresent"], phone_["enrolledViaAde"], phone_["username"]),
                         ("iOS", False, True, "c.tester"))
        self.assertEqual((pad["platform"], pad["supervised"], pad["enrolledViaAde"]), ("iPadOS", False, False))
        self.assertEqual(data["adeInstances"][0]["tokenExpires"], "2027-05-21")
        self.assertEqual(data["vppLocations"][0]["tokenExpires"], "2026-10-16T09:00:00.000Z")
        self.assertEqual(data["apnsCertificate"], {"expires": "2026-10-28"})
        # the normalised export runs through the checks
        i = from_dict(dict(data, collectedAt=ts()))
        codes = {f.code for f in run_all(i)}
        self.assertTrue({"filevault_off", "sip_disabled", "no_passcode", "token_expiring", "apns_expiring",
                         "abm_never_enrolled", "unmanaged_record", "storage_low", "not_ade_enrolled"} <= codes)

    def test_mobile_fallback_to_per_device_detail(self):
        fake = FakeJamf(mobile_detail=False)
        data = export(JamfClient("https://test.jamfcloud.com", "cid", "s", opener=fake), "test", log=lambda *_: None)
        ipad = next(d for d in data["devices"] if d["serial"] == "TSTM000301")
        self.assertEqual((ipad["platform"], ipad["osVersion"], ipad["supervised"], ipad["passcodePresent"],
                          ipad["storageFreeMb"], ipad["username"], ipad["warrantyEnds"]),
                         ("iPadOS", "26.0.1", True, True, 20000, "d.tester", "2027-04-01"))
        self.assertIsNone(data["apnsCertificate"])


class EndToEnd(unittest.TestCase):
    def test_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, data = Path(tmp) / "out", Path(tmp) / "data"
            self.assertEqual(cli.main(["demo", "--out", str(out), "--data", str(data)]), 0)
            for name in ("report.html", "findings.csv", "device_actions.csv", "review.md"):
                self.assertTrue((out / name).stat().st_size > 500, name)
            i = load(data / "jamf_inventory.json")
            self.assertEqual([sum(d.platform == p for d in i.devices) for p in ("macOS", "iOS", "iPadOS")], [18, 14, 8])
            findings = run_all(i, Config(vip=load_vip(data / "vip.txt")))
            self.assertEqual({f.code for f in findings}, set(FIX))          # every check fires at least once
            self.assertTrue(any(f.vip for f in findings))
            with open(out / "device_actions.csv", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["severity"], "critical")
            self.assertEqual(len({r["serial"] for r in rows}), len(rows))   # one row per device
            html = (out / "report.html").read_text(encoding="utf-8")
            for text in ("VIP devices", "OS versions", "Platform tokens", "prefers-color-scheme:dark"):
                self.assertIn(text, html)


if __name__ == "__main__":
    unittest.main()
