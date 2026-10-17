"""The fleet as one JSON file: written by `python -m applefleet export` (or the demo). Schema: docs/export-schema.md."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MAC, IOS, IPADOS = "macOS", "iOS", "iPadOS"
PLATFORMS = [MAC, IOS, IPADOS]
KIND = {MAC: "Mac", IOS: "iPhone", IPADOS: "iPad"}


def parse_ts(value) -> datetime | None:
    """ISO dates and timestamps as Jamf Pro sends them ('2026-10-19', '2026-10-19T07:00:00.123Z', with offset)."""
    if not value:
        return None
    v = str(value).strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)\.(\d+)(.*)$", v)
    if m:                                          # fromisoformat in 3.10 wants exactly 3 or 6 decimals
        v = f"{m.group(1)}.{m.group(2)[:6].ljust(6, '0')}{m.group(3)}"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def version_tuple(value: str | None) -> tuple[int, ...]:
    """'14.10' -> (14, 10, 0); '17.7' and '17.7.0' compare equal; '26.0.1 (a)' keeps only the numbers."""
    nums = [int(n) for n in re.findall(r"\d+", (value or "").split("(")[0].split(" ")[0])[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


@dataclass
class Device:
    id: str
    name: str
    serial: str
    platform: str                    # macOS, iOS, iPadOS (anything else is kept but only partly checked)
    model: str = ""
    os_version: str = ""
    managed: bool = True
    supervised: bool | None = None
    ade: bool | None = None          # enrolled through Automated Device Enrollment (Apple Business Manager)
    user_approved: bool | None = None
    apple_silicon: bool | None = None
    last_contact: datetime | None = None
    last_inventory: datetime | None = None
    username: str = ""
    real_name: str = ""
    filevault: bool | None = None    # None = not collected: the check is skipped, never guessed
    key_escrowed: bool | None = None
    sip: bool | None = None
    gatekeeper: bool | None = None
    firewall: bool | None = None
    bootstrap: bool | None = None
    passcode: bool | None = None
    storage_total_mb: int | None = None
    storage_free_mb: int | None = None
    warranty_end: datetime | None = None

    @property
    def kind(self) -> str:
        return KIND.get(self.platform, self.platform or "Device")

    @property
    def last_seen(self) -> datetime | None:
        seen = [d for d in (self.last_contact, self.last_inventory) if d]
        return max(seen) if seen else None

    @property
    def free_pct(self) -> float | None:
        if not self.storage_total_mb or self.storage_free_mb is None:
            return None
        return 100.0 * self.storage_free_mb / self.storage_total_mb

    @property
    def owner(self) -> str:
        if self.username and self.real_name:
            return f"{self.real_name} ({self.username})"
        return self.real_name or self.username


@dataclass
class Token:
    kind: str                        # APNs, ADE, VPP
    name: str
    expires: datetime | None
    key: str = ""                    # same key = same Apple-side server or location (used to spot a renewal)


@dataclass
class AdeDevice:
    serial: str
    model: str
    description: str
    profile_status: str
    assigned: datetime | None
    instance: str


@dataclass
class Inventory:
    collected_at: datetime
    organisation: str
    devices: list[Device]
    tokens: list[Token] = field(default_factory=list)
    ade_devices: list[AdeDevice] = field(default_factory=list)


def _bool(v) -> bool | None:
    return None if v is None else bool(v)


def _int(v) -> int | None:
    try:
        return None if v is None or v == "" else int(v)
    except (TypeError, ValueError):
        return None


def device_from_dict(d: dict) -> Device:
    return Device(
        id=str(d.get("id", "")), name=d.get("name") or d.get("serial") or "?", serial=d.get("serial") or "",
        platform=d.get("platform") or "", model=d.get("model") or "", os_version=d.get("osVersion") or "",
        managed=d.get("managed", True) is not False, supervised=_bool(d.get("supervised")),
        ade=_bool(d.get("enrolledViaAde")), user_approved=_bool(d.get("userApprovedMdm")),
        apple_silicon=_bool(d.get("appleSilicon")), last_contact=parse_ts(d.get("lastContact")),
        last_inventory=parse_ts(d.get("lastInventory")), username=d.get("username") or "",
        real_name=d.get("realName") or "", filevault=_bool(d.get("fileVaultEnabled")),
        key_escrowed=_bool(d.get("recoveryKeyEscrowed")), sip=_bool(d.get("sipEnabled")),
        gatekeeper=_bool(d.get("gatekeeperEnabled")), firewall=_bool(d.get("firewallEnabled")),
        bootstrap=_bool(d.get("bootstrapTokenEscrowed")), passcode=_bool(d.get("passcodePresent")),
        storage_total_mb=_int(d.get("storageTotalMb")), storage_free_mb=_int(d.get("storageFreeMb")),
        warranty_end=parse_ts(d.get("warrantyEnds")),
    )


def from_dict(d: dict, apns_override: str | None = None) -> Inventory:
    tokens = []
    apns = (d.get("apnsCertificate") or {}).get("expires")
    if apns_override:                              # typed on the command line: wins over the export (renewed since)
        apns = apns_override
    tokens.append(Token("APNs", "MDM push certificate", parse_ts(apns), "apns"))
    for t in d.get("adeInstances") or []:
        tokens.append(Token("ADE", t.get("name") or t.get("serverName") or "Automated Device Enrollment",
                            parse_ts(t.get("tokenExpires")), "ade:" + (t.get("serverUuid") or t.get("name") or "")))
    for t in d.get("vppLocations") or []:
        tokens.append(Token("VPP", t.get("name") or t.get("locationName") or "Apps and Books",
                            parse_ts(t.get("tokenExpires")), "vpp:" + (t.get("locationName") or t.get("name") or "")))
    ade = [AdeDevice(a.get("serial") or "", a.get("model") or "", a.get("description") or "",
                     a.get("profileStatus") or "", parse_ts(a.get("assignedAt")), a.get("instance") or "")
           for a in d.get("adeDevices") or [] if a.get("serial")]
    return Inventory(parse_ts(d.get("collectedAt")) or datetime.now(timezone.utc), d.get("organisation", "fleet"),
                     [device_from_dict(x) for x in d.get("devices") or []], tokens, ade)


def load(path: Path, apns_override: str | None = None) -> Inventory:
    with open(path, encoding="utf-8-sig") as f:
        return from_dict(json.load(f), apns_override)
