"""The checks: platform tokens, OS currency, Mac and mobile security, check-in, storage and warranty, VIP devices."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .model import IOS, IPADOS, MAC, Device, Inventory, version_tuple

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEV_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
BUMP = {INFO: WARNING, WARNING: CRITICAL, CRITICAL: CRITICAL}
AREAS = ["Platform", "OS currency", "Mac security", "Mobile security", "Enrollment", "Hardware"]
FLEET = "Jamf Pro"          # subject of fleet-wide findings

FIX = {
    "apns_expiring": "Renew the push certificate in Jamf Pro (Settings > Global > Push certificates > Renew) with the "
                     "SAME Apple Account that created it on identity.apple.com/pushcert. Never create a new one: a "
                     "new certificate means every device has to re-enroll. See docs/weekly-review-runbook.md.",
    "token_expiring": "Download a new token in Apple Business Manager (ADE: Preferences > your MDM server > Download "
                      "token; Apps and Books: Preferences > Payments and billing > content token) and upload it to "
                      "the SAME instance or location in Jamf Pro with Renew. Do not create a second one.",
    "os_unsupported": "This major version no longer gets security fixes. Upgrade it, or replace the device if the "
                      "hardware cannot run a supported version. Until then, keep it off sensitive data.",
    "os_below_minimum": "Below the security baseline. Push the update (Jamf Pro managed software updates / DDM) "
                        "with a deadline; check why it is stuck if it was already pushed (storage, bootstrap token).",
    "filevault_off": "The disk is not encrypted: a lost Mac is a data breach. Scope the FileVault configuration "
                     "profile to it and confirm the personal recovery key is escrowed to Jamf Pro.",
    "filevault_key_not_escrowed": "FileVault is on but Jamf Pro has no valid personal recovery key: if the user "
                                  "forgets the password, the data is gone. Run a key reissue policy for this Mac.",
    "sip_disabled": "System Integrity Protection is off: malware can change system files. Boot into recovery, "
                    "run `csrutil enable` and ask the user why it was turned off.",
    "gatekeeper_off": "Gatekeeper is off, so unsigned apps run without a warning. Re-enable it with a configuration "
                      "profile (System Policy) so the user cannot turn it off again.",
    "firewall_off": "The application firewall is off. Turn it on with a configuration profile (Firewall payload).",
    "bootstrap_token_missing": "No bootstrap token escrowed on an Apple silicon Mac: Jamf Pro cannot install "
                               "software updates or kernel extensions without the user. Have a secure-token user "
                               "log in (or run `profiles install -type bootstraptoken`) and check inventory again.",
    "mdm_not_user_approved": "The MDM enrollment is not user-approved or not supervised, so some profiles and "
                             "update commands are refused. Approve the profile in System Settings, or re-enroll "
                             "through Automated Device Enrollment at the next rebuild.",
    "no_passcode": "No passcode: anyone holding the device sees the mail and the apps. Scope a passcode "
                   "configuration profile and a compliance rule; contact the user today.",
    "not_supervised": "Not supervised: many restrictions, silent app installs and Lost Mode do not apply. "
                      "Supervision needs a wipe and enrollment through Automated Device Enrollment.",
    "not_ade_enrolled": "Enrolled by hand, not through Automated Device Enrollment: the user can remove the MDM "
                        "profile at any time. Assign it in Apple Business Manager and re-enroll at the next reset.",
    "checkin_stale": "Not seen for a while. Contact the user; a device that has been gone for weeks is probably "
                     "lost, wiped or in a drawer. Lock or wipe if lost; otherwise retire the record.",
    "unmanaged_record": "Inventory record without management. Delete it, or re-enroll the device if it is in use.",
    "abm_never_enrolled": "Assigned to this MDM server in Apple Business Manager but never enrolled. Find it (stock "
                          "cupboard, new starter, sold?); enroll it, or release it from the organisation in ABM.",
    "storage_low": "Disk almost full: updates fail and the device slows down. Ask the user to clean up or plan "
                   "a bigger device.",
    "warranty_ending": "Warranty or AppleCare ends soon. Decide now: extend (it can only be bought before it "
                       "lapses) or plan the replacement.",
    "warranty_ended": "Warranty ended and the device is still in use. Add it to the replacement plan.",
}


@dataclass
class Finding:
    code: str
    area: str
    severity: str
    device: str
    detail: str
    serial: str = ""
    owner: str = ""
    vip: bool = False

    @property
    def fix(self) -> str:
        return FIX.get(self.code, "")


@dataclass
class Config:
    token_warning_days: int = 30
    token_critical_days: int = 14
    stale_days: int = 14
    lost_days: int = 45
    storage_warning_pct: float = 10
    storage_critical_pct: float = 5
    warranty_days: int = 60
    # Security baseline: below the minimum = warning; below the oldest supported major = critical
    minimum: dict[str, str] = field(default_factory=lambda: {MAC: "15.7", IOS: "18.7", IPADOS: "18.7"})
    oldest_major: dict[str, int] = field(default_factory=lambda: {MAC: 14, IOS: 17, IPADOS: 17})
    vip: set[str] = field(default_factory=set)


def days_left(now: datetime, end: datetime | None) -> float | None:
    return None if end is None else (end - now).total_seconds() / 86400


def load_vip(path) -> set[str]:
    """One username per line; blank lines and '#' comments ignored; case does not matter."""
    with open(path, encoding="utf-8-sig") as f:
        return {ln.split("#")[0].strip().lower() for ln in f if ln.split("#")[0].strip()}


def _f(code, area, sev, d: Device, detail) -> Finding:
    return Finding(code, area, sev, d.name, detail, d.serial, d.owner)


def check_platform(inv: Inventory, c: Config) -> list[Finding]:
    out = []
    now = inv.collected_at
    for t in inv.tokens:
        left = days_left(now, t.expires)
        if left is None or left > c.token_warning_days:
            continue
        # renewed as a second instance for the same Apple-side server: the newer one carries the service
        if any(o is not t and o.key == t.key and (days_left(now, o.expires) or 0) > c.token_warning_days
               for o in inv.tokens):
            continue
        sev = CRITICAL if left <= c.token_critical_days else WARNING
        when = f"expired {-left:.0f} days ago" if left <= 0 else f"expires in {left:.0f} days"
        if t.kind == "APNs":
            out.append(Finding("apns_expiring", AREAS[0], sev, FLEET,
                               f"APNs push certificate {when} ({t.expires:%Y-%m-%d}). If it lapses, no device "
                               "receives MDM commands; if it is replaced instead of renewed, all must re-enroll."))
        else:
            label = "ADE server token" if t.kind == "ADE" else "Apps and Books (VPP) token"
            effect = ("new devices cannot enroll through ABM" if t.kind == "ADE"
                      else "apps stop installing and updating")
            out.append(Finding("token_expiring", AREAS[0], sev, FLEET,
                               f"{label} '{t.name}' {when} ({t.expires:%Y-%m-%d}): {effect}."))
    return out


def os_status(platform: str, version: str, c: Config) -> str:
    """ok, warning (below minimum) or critical (unsupported major) for one OS version."""
    if platform not in c.minimum or not version:
        return "ok"
    v = version_tuple(version)
    if v[0] < c.oldest_major.get(platform, 0):
        return CRITICAL
    if v < version_tuple(c.minimum[platform]):
        return WARNING
    return "ok"


def check_os(d: Device, c: Config) -> list[Finding]:
    st = os_status(d.platform, d.os_version, c)
    if st == CRITICAL:
        return [_f("os_unsupported", AREAS[1], CRITICAL, d,
                   f"{d.platform} {d.os_version}: major version {version_tuple(d.os_version)[0]} is no longer "
                   f"supported (oldest supported: {c.oldest_major[d.platform]}).")]
    if st == WARNING:
        return [_f("os_below_minimum", AREAS[1], WARNING, d,
                   f"{d.platform} {d.os_version} is below the minimum {c.minimum[d.platform]}.")]
    return []


def check_mac(d: Device) -> list[Finding]:
    if d.platform != MAC:
        return []
    out = []
    a = AREAS[2]
    if d.filevault is False:
        out.append(_f("filevault_off", a, CRITICAL, d, "FileVault is off."))
    elif d.filevault and d.key_escrowed is False:
        out.append(_f("filevault_key_not_escrowed", a, WARNING, d,
                      "FileVault on, but no valid personal recovery key in Jamf Pro."))
    if d.sip is False:
        out.append(_f("sip_disabled", a, CRITICAL, d, "System Integrity Protection disabled."))
    if d.gatekeeper is False:
        out.append(_f("gatekeeper_off", a, WARNING, d, "Gatekeeper disabled."))
    if d.firewall is False:
        out.append(_f("firewall_off", a, WARNING, d, "Application firewall off."))
    if d.apple_silicon and d.bootstrap is False:
        out.append(_f("bootstrap_token_missing", a, WARNING, d,
                      "Apple silicon Mac without an escrowed bootstrap token: MDM software updates will not install."))
    gaps = [txt for ok, txt in ((d.user_approved, "not user-approved"), (d.supervised, "not supervised")) if ok is False]
    if gaps:
        out.append(_f("mdm_not_user_approved", a, WARNING, d, "MDM enrollment " + " and ".join(gaps) + "."))
    return out


def check_mobile(d: Device) -> list[Finding]:
    if d.platform not in (IOS, IPADOS):
        return []
    out = []
    a = AREAS[3]
    if d.passcode is False:
        out.append(_f("no_passcode", a, CRITICAL, d, f"{d.kind} without a passcode."))
    if d.supervised is False:
        out.append(_f("not_supervised", a, WARNING, d, f"{d.kind} is not supervised."))
    if d.ade is False:
        out.append(_f("not_ade_enrolled", a, WARNING, d,
                      "Managed but not enrolled through ADE: the user can remove the MDM profile."))
    return out


def check_checkin(d: Device, now: datetime, c: Config) -> list[Finding]:
    seen = d.last_seen
    if seen is None:
        return [_f("checkin_stale", AREAS[4], WARNING, d, "No check-in or inventory date recorded.")]
    days = (now - seen).days
    if days > c.lost_days:
        return [_f("checkin_stale", AREAS[4], CRITICAL, d,
                   f"Last check-in {days} days ago ({seen:%Y-%m-%d}): probably lost, wiped or out of use.")]
    if days > c.stale_days:
        return [_f("checkin_stale", AREAS[4], WARNING, d, f"Last check-in {days} days ago ({seen:%Y-%m-%d}).")]
    return []


def check_hardware(d: Device, now: datetime, c: Config) -> list[Finding]:
    out = []
    pct = d.free_pct
    if pct is not None and pct < c.storage_warning_pct:
        sev = CRITICAL if pct < c.storage_critical_pct else WARNING
        out.append(_f("storage_low", AREAS[5], sev, d,
                      f"{pct:.0f}% free ({d.storage_free_mb / 1024:.1f} of {d.storage_total_mb / 1024:.0f} GB)."))
    left = days_left(now, d.warranty_end)
    if left is not None:
        in_use = d.last_seen is not None and (now - d.last_seen).days <= c.lost_days
        if 0 < left <= c.warranty_days:
            out.append(_f("warranty_ending", AREAS[5], WARNING, d,
                          f"Warranty / AppleCare ends in {left:.0f} days ({d.warranty_end:%Y-%m-%d})."))
        elif left <= 0 and in_use:
            out.append(_f("warranty_ended", AREAS[5], INFO, d,
                          f"Warranty ended {d.warranty_end:%Y-%m-%d}; device still in use."))
    return out


def check_abm(inv: Inventory) -> list[Finding]:
    known = {d.serial.upper() for d in inv.devices if d.serial}
    out = []
    for a in inv.ade_devices:
        if a.serial.upper() in known:
            continue
        since = f" since {a.assigned:%Y-%m-%d}" if a.assigned else ""
        hint = " No PreStage enrollment assigned to it." if a.profile_status.upper() in ("EMPTY", "") else ""
        out.append(Finding("abm_never_enrolled", AREAS[4], WARNING, a.serial,
                           f"{a.model or 'Device'} assigned in Apple Business Manager{since} but never enrolled "
                           f"(profile status {a.profile_status or 'unknown'}).{hint}", a.serial))
    return out


def apply_vip(findings: list[Finding], inv: Inventory, c: Config) -> list[Finding]:
    """Findings on a VIP user's device go one level up and are marked, so they are dealt with before the meeting."""
    if not c.vip:
        return findings
    vip_serials = {d.serial for d in inv.devices if d.username.lower() in c.vip}
    for f in findings:
        if f.serial and f.serial in vip_serials:
            f.vip = True
            f.severity = BUMP[f.severity]
            f.detail += " (VIP)"
    return findings


def run_all(inv: Inventory, c: Config | None = None) -> list[Finding]:
    c = c or Config()
    now = inv.collected_at
    findings = check_platform(inv, c)
    for d in inv.devices:
        if not d.managed:
            findings.append(_f("unmanaged_record", AREAS[4], INFO, d, f"Unmanaged {d.kind} record."))
            continue
        findings += check_os(d, c) + check_mac(d) + check_mobile(d) + check_checkin(d, now, c) + check_hardware(d, now, c)
    findings += check_abm(inv)
    apply_vip(findings, inv, c)
    return sorted(findings, key=lambda f: (SEV_ORDER[f.severity], AREAS.index(f.area), not f.vip,
                                           f.device.lower(), f.code))


def area_status(findings: list[Finding]) -> dict[str, str]:
    status = {a: "ok" for a in AREAS}
    for f in findings:
        if status[f.area] == "ok" or SEV_ORDER[f.severity] < SEV_ORDER[status[f.area]]:
            status[f.area] = f.severity
    return status


def token_calendar(inv: Inventory) -> list[dict]:
    """Every platform token with its days left, soonest first (unknown dates last)."""
    rows = [{"kind": t.kind, "name": t.name, "expires": t.expires,
             "days": None if t.expires is None else round(days_left(inv.collected_at, t.expires))}
            for t in inv.tokens]
    return sorted(rows, key=lambda r: (r["expires"] is None, r["expires"] or inv.collected_at))


def token_status(days: int | None, c: Config) -> str:
    if days is None:
        return "info"
    return CRITICAL if days <= c.token_critical_days else WARNING if days <= c.token_warning_days else "ok"


def _platform_of_model(model: str) -> str:
    m = model.lower()
    return IPADOS if "ipad" in m else IOS if "iphone" in m else MAC if "mac" in m else ""


def device_actions(inv: Inventory, findings: list[Finding]) -> list[dict]:
    """One row per device with everything wrong with it: the technician's work list, worst first."""
    by_serial: dict[str, list[Finding]] = {}
    for f in findings:
        if f.area != "Platform":
            by_serial.setdefault(f.serial or f.device, []).append(f)
    devices = {d.serial or d.name: d for d in inv.devices}
    abm = {a.serial: a for a in inv.ade_devices}
    rows = []
    for key, fs in by_serial.items():
        d = devices.get(key)
        worst = min(fs, key=lambda f: SEV_ORDER[f.severity]).severity
        steps = []
        for f in fs:
            if f.fix not in steps:
                steps.append(f.fix)
        seen = d.last_seen if d else None
        rows.append({"severity": worst, "device": fs[0].device, "serial": fs[0].serial,
                     "platform": d.platform if d else _platform_of_model(abm[key].model if key in abm else ""),
                     "model": d.model if d else (abm[key].model if key in abm else ""),
                     "os": d.os_version if d else "", "owner": fs[0].owner, "vip": any(f.vip for f in fs),
                     "last_seen_days": "" if seen is None else (inv.collected_at - seen).days,
                     "count": len(fs), "issues": "; ".join(f.detail for f in fs), "next_steps": " | ".join(steps),
                     "_sort": (SEV_ORDER[worst], not any(f.vip for f in fs),
                               -sum(f.severity == CRITICAL for f in fs), -len(fs), fs[0].device.lower())})
    rows.sort(key=lambda r: r["_sort"])
    return rows
