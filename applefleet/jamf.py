"""Read-only export from the Jamf Pro API into the tool's own JSON (docs/export-schema.md). Standard library only.

Authentication: a Jamf Pro API client (Settings > System > API roles and clients) with client credentials.
The secret is read from the JAMF_CLIENT_SECRET environment variable, never from the command line.
Privileges: Read Computers, Read Mobile Devices, Read Device Enrollment Program Instances,
Read Volume Purchasing Locations.

Field names follow the public Jamf Pro API reference and are read defensively (.get with defaults): a field that
is missing in your version becomes null and the check that needs it is skipped. Not yet tested against a live
Jamf Pro instance.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Callable

COMPUTER_SECTIONS = ["GENERAL", "HARDWARE", "OPERATING_SYSTEM", "SECURITY", "DISK_ENCRYPTION", "STORAGE",
                     "USER_AND_LOCATION", "PURCHASING"]
MOBILE_SECTIONS = ["GENERAL", "HARDWARE", "SECURITY", "USER_AND_LOCATION", "PURCHASING"]


class JamfClient:
    """Tiny Jamf Pro API client: OAuth client credentials, token refresh, page/page-size paging."""

    def __init__(self, url: str, client_id: str, client_secret: str, page_size: int = 100,
                 opener: Callable = urllib.request.urlopen):
        self.base = url.rstrip("/")
        self.client_id, self.client_secret = client_id, client_secret
        self.page_size = page_size
        self.opener = opener
        self._token, self._expires = "", 0.0

    def _token_value(self) -> str:
        if not self._token or time.time() > self._expires - 30:
            body = urllib.parse.urlencode({"client_id": self.client_id, "client_secret": self.client_secret,
                                           "grant_type": "client_credentials"}).encode()
            req = urllib.request.Request(self.base + "/api/oauth/token", data=body, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                                  "Accept": "application/json"})
            with self.opener(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8"))
            self._token = data.get("access_token", "")
            self._expires = time.time() + float(data.get("expires_in") or 60)
            if not self._token:
                raise RuntimeError("Jamf Pro returned no access token: check the client ID, secret and API role.")
        return self._token

    def get(self, path: str, params: list[tuple[str, object]] | None = None) -> dict:
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + self._token_value(),
                                                   "Accept": "application/json"})
        with self.opener(req, timeout=120) as r:
            return json.loads(r.read().decode("utf-8") or "{}")

    def paged(self, path: str, params: list[tuple[str, object]] | None = None) -> list[dict]:
        out: list[dict] = []
        page = 0
        while True:
            data = self.get(path, list(params or []) + [("page", page), ("page-size", self.page_size)])
            results = data.get("results") or []
            out += results
            total = data.get("totalCount")
            if not results or (total is not None and len(out) >= int(total)) or \
                    (total is None and len(results) < self.page_size):
                return out
            page += 1


# ---------------------------------------------------------------- normalisation (one raw record -> our schema)

def _sec(raw: dict, *names) -> dict:
    """First section present under any of the given names (camelCase in v1/v2, older shapes vary)."""
    for n in names:
        v = raw.get(n)
        if isinstance(v, dict):
            return v
    return {}


def _enum(value, true: set[str], false: set[str]) -> bool | None:
    v = str(value or "").upper()
    return True if v in true else False if v in false else None


def platform_of(model_identifier: str, model: str, device_type: str = "") -> str:
    ident = (model_identifier or "").lower()
    text = (model or "").lower()
    if ident.startswith("ipad") or "ipad" in text:
        return "iPadOS"
    if ident.startswith("iphone") or "iphone" in text:
        return "iOS"
    return device_type or "other"


def normalise_computer(raw: dict) -> dict:
    g = _sec(raw, "general")
    hw = _sec(raw, "hardware")
    os_ = _sec(raw, "operatingSystem")
    sec = _sec(raw, "security")
    enc = _sec(raw, "diskEncryption")
    st = _sec(raw, "storage")
    user = _sec(raw, "userAndLocation")
    buy = _sec(raw, "purchasing")
    boot = enc.get("bootPartitionEncryptionDetails") or {}
    fv = _enum(boot.get("partitionFileVault2State"), {"ENCRYPTED", "ENCRYPTING"}, {"UNENCRYPTED", "DECRYPTING"})
    if fv is None:
        fv = _enum(os_.get("fileVault2Status"), {"ALL_ENCRYPTED", "BOOT_ENCRYPTED"}, {"NOT_ENCRYPTED"})
    # Jamf shows UNKNOWN when it holds no personal recovery key for an encrypted Mac
    key = _enum(enc.get("individualRecoveryKeyValidityStatus"), {"VALID"}, {"INVALID", "UNKNOWN"})
    silicon = hw.get("appleSilicon")
    if silicon is None and hw.get("processorArchitecture"):
        silicon = str(hw.get("processorArchitecture")).lower() in ("arm64", "arm64e")
    total = free = None
    for disk in st.get("disks") or []:
        for part in disk.get("partitions") or []:
            if str(part.get("partitionType", "")).upper() == "BOOT":
                total, free = part.get("sizeMegabytes"), part.get("availableMegabytes")
        if total is None and disk.get("sizeMegabytes"):
            total = disk.get("sizeMegabytes")
    if st.get("bootDriveAvailableSpaceMegabytes") is not None:
        free = st.get("bootDriveAvailableSpaceMegabytes")
    managed = (g.get("remoteManagement") or {}).get("managed")
    return {
        "id": str(raw.get("id", "")), "name": g.get("name") or hw.get("serialNumber") or "?",
        "serial": hw.get("serialNumber") or "", "platform": "macOS", "model": hw.get("model") or "",
        "osVersion": os_.get("version") or "", "managed": managed is not False,
        "supervised": g.get("supervised"), "enrolledViaAde": g.get("enrolledViaAutomatedDeviceEnrollment"),
        "userApprovedMdm": g.get("userApprovedMdm"), "appleSilicon": silicon,
        "lastContact": g.get("lastContactTime"), "lastInventory": g.get("reportDate"),
        "username": user.get("username") or "", "realName": user.get("realname") or user.get("realName") or "",
        "fileVaultEnabled": fv, "recoveryKeyEscrowed": key,
        "sipEnabled": _enum(sec.get("sipStatus"), {"ENABLED"}, {"DISABLED"}),
        "gatekeeperEnabled": _enum(sec.get("gatekeeperStatus"),
                                   {"APP_STORE_AND_IDENTIFIED_DEVELOPERS", "APP_STORE"}, {"DISABLED"}),
        "firewallEnabled": sec.get("firewallEnabled"),
        "bootstrapTokenEscrowed": _enum(sec.get("bootstrapTokenEscrowedStatus"), {"ESCROWED"}, {"NOT_ESCROWED"}),
        "passcodePresent": None, "storageTotalMb": total, "storageFreeMb": free,
        "warrantyEnds": buy.get("warrantyDate") or None,
    }


def normalise_mobile(raw: dict) -> dict:
    """Accepts both the paged /api/v2/mobile-devices/detail record and the per-device /{id}/detail shape."""
    g = _sec(raw, "general")
    hw = _sec(raw, "hardware")
    sec = _sec(raw, "security")
    user = _sec(raw, "userAndLocation", "location")
    buy = _sec(raw, "purchasing")
    ios = _sec(raw, "ios", "ipados")                       # per-device detail nests the iOS part here
    sec = sec or _sec(ios, "security")
    buy = buy or _sec(ios, "purchasing")
    model = hw.get("model") or ios.get("model") or raw.get("model") or ""
    ident = hw.get("modelIdentifier") or ios.get("modelIdentifier") or raw.get("modelIdentifier") or ""
    ade = g.get("enrolledViaAutomatedDeviceEnrollment")
    if ade is None and "enrollmentMethodPrestage" in g:       # present but null: not enrolled with a PreStage
        prestage = g.get("enrollmentMethodPrestage") or {}
        ade = bool(prestage.get("mobileDevicePrestageId") or prestage.get("profileName"))
    supervised = g.get("supervised", ios.get("supervised"))
    total = hw.get("capacityMb", ios.get("capacityMb"))
    free = hw.get("availableSpaceMb", ios.get("availableMb"))
    managed = g.get("managed", raw.get("managed"))
    return {
        "id": str(raw.get("mobileDeviceId") or raw.get("id") or ""),
        "name": g.get("displayName") or raw.get("name") or hw.get("serialNumber") or "?",
        "serial": hw.get("serialNumber") or raw.get("serialNumber") or "",
        "platform": platform_of(ident, model, raw.get("deviceType") or ""), "model": model,
        "osVersion": g.get("osVersion") or raw.get("osVersion") or "", "managed": managed is not False,
        "supervised": supervised, "enrolledViaAde": ade, "userApprovedMdm": None, "appleSilicon": None,
        "lastContact": None,
        "lastInventory": g.get("lastInventoryUpdateDate") or raw.get("lastInventoryUpdateTimestamp"),
        "username": user.get("username") or "", "realName": user.get("realName") or user.get("realname") or "",
        "passcodePresent": sec.get("passcodePresent"), "storageTotalMb": total, "storageFreeMb": free,
        "warrantyEnds": buy.get("warrantyExpiresDate") or None,
    }


def export(client: JamfClient, organisation: str, apns_expires: str | None = None, log=print) -> dict:
    computers = client.paged("/api/v1/computers-inventory",
                             [("section", s) for s in COMPUTER_SECTIONS] + [("sort", "id:asc")])
    log(f"  computers: {len(computers)}")
    try:
        mobiles = client.paged("/api/v2/mobile-devices/detail",
                               [("section", s) for s in MOBILE_SECTIONS] + [("sort", "mobileDeviceId:asc")])
    except urllib.error.HTTPError as e:
        if e.code not in (400, 404):
            raise
        log("  /api/v2/mobile-devices/detail not available; reading devices one by one")
        mobiles = [client.get(f"/api/v2/mobile-devices/{m.get('id')}/detail")
                   for m in client.paged("/api/v2/mobile-devices")]
    log(f"  mobile devices: {len(mobiles)}")
    instances = client.get("/api/v1/device-enrollments").get("results") or []
    ade_devices = []
    for inst in instances:
        try:
            rows = client.get(f"/api/v1/device-enrollments/{inst.get('id')}/devices").get("results") or []
        except urllib.error.HTTPError:
            rows = []
        ade_devices += [{"serial": r.get("serialNumber") or "", "model": r.get("model") or "",
                         "description": r.get("description") or r.get("model") or "",
                         "profileStatus": r.get("profileStatus") or "",
                         "assignedAt": r.get("deviceAssignedDate") or r.get("profileAssignTime"),
                         "instance": inst.get("name") or ""} for r in rows]
    vpp = client.get("/api/v1/volume-purchasing-locations").get("results") or []
    log(f"  ADE instances: {len(instances)} ({len(ade_devices)} devices assigned in ABM) · VPP locations: {len(vpp)}")
    return {
        "schema": "applefleet/1",
        "collectedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organisation": organisation, "source": "Jamf Pro API",
        "apnsCertificate": {"expires": apns_expires} if apns_expires else None,
        "adeInstances": [{"id": str(i.get("id", "")), "name": i.get("name") or "", "serverName": i.get("serverName") or "",
                          "serverUuid": i.get("serverUuid") or "", "tokenExpires": i.get("tokenExpirationDate")}
                         for i in instances],
        "vppLocations": [{"id": str(v.get("id", "")), "name": v.get("name") or "",
                          "locationName": v.get("locationName") or "", "tokenExpires": v.get("tokenExpiration")}
                         for v in vpp],
        "adeDevices": ade_devices,
        "devices": [normalise_computer(c) for c in computers] + [normalise_mobile(m) for m in mobiles],
    }
