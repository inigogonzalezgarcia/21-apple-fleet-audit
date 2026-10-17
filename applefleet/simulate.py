"""Fictional demo fleet (contoso.example): 18 Macs, 14 iPhones and 8 iPads managed in Jamf Pro, enrolled from
Apple Business Manager.

People, serial numbers, dates and settings are invented; nothing here comes from a real fleet. Faults are placed
on purpose so every check fires at least once. Fixed DEMO_NOW and a seeded random generator: same output every run.
"""
from __future__ import annotations

import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEMO_NOW = datetime(2026, 10, 19, 7, 0, tzinfo=timezone.utc)
VIP_USERS = ["e.navarro", "j.whitfield", "a.okafor"]

_rng = random.Random(21)


def _ts(**delta) -> str:
    return (DEMO_NOW + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _day(days: int) -> str:
    return (DEMO_NOW + timedelta(days=days)).strftime("%Y-%m-%d")


def _serial(old: bool = False) -> str:
    """Apple serials: 12 characters before 2021, 10 random characters after."""
    chars = string.ascii_uppercase.replace("O", "").replace("I", "") + string.digits
    return "".join(_rng.choice(chars) for _ in range(12 if old else 10))


MACS = {  # model -> (Apple silicon, storage in GB)
    "MacBook Pro (14-inch, M3 Pro, 2023)": (True, 1000), "MacBook Pro (14-inch, M4, 2024)": (True, 512),
    "MacBook Air (13-inch, M2, 2022)": (True, 256), "MacBook Air (15-inch, M3, 2024)": (True, 512),
    "Mac mini (M2, 2023)": (True, 512), "MacBook Pro (16-inch, 2019)": (False, 512),
    "iMac (Retina 5K, 27-inch, 2017)": (False, 1000), "MacBook Air (13-inch, 2017)": (False, 128),
    "MacBook Pro (13-inch, 2020, Four Thunderbolt 3 ports)": (False, 512),
}


def mac(name, user="", real="", model="MacBook Air (13-inch, M2, 2022)", os="26.0.1", **over) -> dict:
    silicon, gb = MACS[model]
    total = gb * 1024
    d = {"id": str(len(_ids) + 1), "name": name, "serial": _serial(old=not silicon), "platform": "macOS",
         "model": model, "osVersion": os, "managed": True, "supervised": True, "enrolledViaAde": True,
         "userApprovedMdm": True, "appleSilicon": silicon, "lastContact": _ts(hours=-_rng.randint(1, 60)),
         "lastInventory": _ts(hours=-_rng.randint(4, 140)), "username": user, "realName": real,
         "fileVaultEnabled": True, "recoveryKeyEscrowed": True, "sipEnabled": True, "gatekeeperEnabled": True,
         "firewallEnabled": True, "bootstrapTokenEscrowed": True if silicon else None, "passcodePresent": None,
         "storageTotalMb": total, "storageFreeMb": int(total * _rng.uniform(0.22, 0.61)),
         "warrantyEnds": _day(_rng.randint(120, 900) if silicon else -_rng.randint(200, 900))}
    d.update(over)
    _ids.append(d["id"])
    return d


def mobile(name, kind, user="", real="", model="", os="26.0.1", gb=128, **over) -> dict:
    platform = "iOS" if kind == "iPhone" else "iPadOS"
    total = gb * 1024
    d = {"id": str(len(_ids) + 1), "name": name, "serial": _serial(), "platform": platform, "model": model,
         "osVersion": os, "managed": True, "supervised": True, "enrolledViaAde": True, "userApprovedMdm": None,
         "appleSilicon": None, "lastContact": None, "lastInventory": _ts(hours=-_rng.randint(2, 70)),
         "username": user, "realName": real, "passcodePresent": True, "storageTotalMb": total,
         "storageFreeMb": int(total * _rng.uniform(0.18, 0.7)), "warrantyEnds": _day(_rng.randint(90, 700))}
    d.update(over)
    _ids.append(d["id"])
    return d


_ids: list[str] = []


def demo_inventory() -> dict:
    global _rng
    _rng = random.Random(21)
    _ids.clear()
    p14, p14m4, air2, air3 = ("MacBook Pro (14-inch, M3 Pro, 2023)", "MacBook Pro (14-inch, M4, 2024)",
                              "MacBook Air (13-inch, M2, 2022)", "MacBook Air (15-inch, M3, 2024)")
    devices = [
        # --- Macs (18) ---
        mac("MBP-ENAVARRO", "e.navarro", "Elena Navarro", p14m4, recoveryKeyEscrowed=False),   # VIP, key missing
        mac("MBA-JWHITFIELD", "j.whitfield", "James Whitfield", air3, storageFreeMb=41000),    # VIP, 8% free
        mac("MBP-AOKAFOR", "a.okafor", "Amara Okafor", p14),
        mac("MBP-DROMERO", "d.romero", "Daniel Romero", "MacBook Pro (16-inch, 2019)", "14.7.6",
            fileVaultEnabled=False),                                                         # not encrypted
        mac("MBP-DEV-PKOWALSKI", "p.kowalski", "Piotr Kowalski", p14, sipEnabled=False),     # SIP off
        mac("MBA-LMARTIN", "l.martin", "Lucia Martin", air2, bootstrapTokenEscrowed=False),  # no bootstrap token
        mac("IMAC-RECEPTION", "", "", "iMac (Retina 5K, 27-inch, 2017)", "13.7.8"),          # unsupported macOS
        mac("MBA-WAREHOUSE-01", "t.haddad", "Tariq Haddad", "MacBook Air (13-inch, 2017)", "12.7.6",
            storageFreeMb=9000),                                                             # unsupported, 7% free
        mac("MBP-SBERG", "s.berg", "Sofia Berg", p14m4, "26.1", gatekeeperEnabled=False),
        mac("MBA-RKHAN", "r.khan", "Ravi Khan", air3, "15.7.1", firewallEnabled=False),
        mac("MBP-MDESIGN-02", "m.duarte", "Marta Duarte", "MacBook Pro (13-inch, 2020, Four Thunderbolt 3 ports)",
            "15.6.1", supervised=False, userApprovedMdm=False, enrolledViaAde=False),        # enrolled by hand
        mac("MBA-CFOSTER", "c.foster", "Chloe Foster", air2, lastContact=_ts(days=-60),
            lastInventory=_ts(days=-61)),                                                    # gone for 60 days
        mac("MBP-VIDEO-01", "n.ortega", "Nora Ortega", p14, storageFreeMb=40000),           # 4% free
        mac("MBA-OLD-LOANER", "", "", air2, managed=False, lastContact=_ts(days=-140),
            lastInventory=_ts(days=-140)),                                                   # unmanaged record
        mac("MBA-HLINDQVIST", "h.lindqvist", "Henrik Lindqvist", air3, lastContact=_ts(days=-19),
            lastInventory=_ts(days=-19)),                                                    # 19 days
        mac("MINI-BUILD-01", "", "", "Mac mini (M2, 2023)", "26.1", warrantyEnds=_day(41)),
        mac("MBA-GPATEL", "g.patel", "Grace Patel", air3, "26.1"),
        mac("MBP-BMORENO", "b.moreno", "Bruno Moreno", p14m4, "15.7.1"),
        # --- iPhones (14) ---
        mobile("iPhone-ENAVARRO", "iPhone", "e.navarro", "Elena Navarro", "iPhone 16 Pro", "18.6.2", 256),  # VIP
        mobile("iPhone-JWHITFIELD", "iPhone", "j.whitfield", "James Whitfield", "iPhone 16 Pro", "26.0.1", 256),
        mobile("iPhone-AOKAFOR", "iPhone", "a.okafor", "Amara Okafor", "iPhone 15 Pro", "26.0.1", 256),
        mobile("iPhone-SIBRAHIM", "iPhone", "s.ibrahim", "Samir Ibrahim", "iPhone 14", "18.7.1",
               passcodePresent=False),                                                       # no passcode
        mobile("iPhone-WAREHOUSE-03", "iPhone", "", "", "iPhone 8", "16.7.10", 64),         # unsupported iOS
        mobile("iPhone-KNOVAK", "iPhone", "k.novak", "Katarina Novak", "iPhone 13", "17.7.2"),
        mobile("iPhone-FDIAZ", "iPhone", "f.diaz", "Felipe Diaz", "iPhone 15", "26.0.1", supervised=False,
               enrolledViaAde=False),                                                        # enrolled by hand
        mobile("iPhone-AMURPHY", "iPhone", "a.murphy", "Aoife Murphy", "iPhone 15", "26.0.1",
               lastInventory=_ts(days=-22)),
        mobile("iPhone-YTANAKA", "iPhone", "y.tanaka", "Yuki Tanaka", "iPhone 14", "26.0.1", 128,
               storageFreeMb=9500),                                                          # 7% free
        mobile("iPhone-LROSSI", "iPhone", "l.rossi", "Luca Rossi", "iPhone 16", "26.1"),
        mobile("iPhone-OADEYEMI", "iPhone", "o.adeyemi", "Ola Adeyemi", "iPhone 16", "26.1"),
        mobile("iPhone-IFERREIRA", "iPhone", "i.ferreira", "Ines Ferreira", "iPhone 15", "18.7.1",
               warrantyEnds=_day(23)),
        mobile("iPhone-MSCHMIDT", "iPhone", "m.schmidt", "Max Schmidt", "iPhone 16", "26.0.1"),
        mobile("iPhone-ONCALL-IT", "iPhone", "", "", "iPhone 15", "26.0.1"),
        # --- iPads (8) ---
        mobile("iPad-AOKAFOR-BOARD", "iPad", "a.okafor", "Amara Okafor", "iPad Pro 13-inch (M4)", "26.0.1", 512,
               lastInventory=_ts(days=-18)),                                                 # VIP board iPad
        mobile("iPad-ENAVARRO", "iPad", "e.navarro", "Elena Navarro", "iPad Air 11-inch (M2)", "26.0.1", 256),
        mobile("iPad-ROOM-ATLAS", "iPad", "", "", "iPad (10th generation)", "18.7.1", 64),
        mobile("iPad-ROOM-BOREAS", "iPad", "", "", "iPad (10th generation)", "26.0.1", 64),
        mobile("iPad-SALES-DEMO", "iPad", "v.costa", "Vera Costa", "iPad Air 11-inch (M2)", "26.0.1",
               supervised=False, enrolledViaAde=False),                                      # unsupervised
        mobile("iPad-TRAINING-02", "iPad", "", "", "iPad (9th generation)", "16.7.10", 64,
               lastInventory=_ts(days=-75)),                                                 # gone and outdated
        mobile("iPad-FIELD-04", "iPad", "j.brennan", "Jack Brennan", "iPad mini (A17 Pro)", "18.7.1", 128),
        mobile("iPad-ROOM-CASTOR", "iPad", "", "", "iPad (10th generation)", "26.1", 64),
    ]
    ade_devices = [{"serial": d["serial"], "model": d["model"], "description": d["model"],
                    "profileStatus": "PUSHED", "assignedAt": _day(-400), "instance": "Contoso ABM"}
                   for d in devices if d["enrolledViaAde"] and d["managed"]]
    ade_devices.append({"serial": _serial(), "model": "iPad Air 11-inch (M2)", "description": "iPad Air 11-inch (M2)",
                        "profileStatus": "ASSIGNED", "assignedAt": _day(-34), "instance": "Contoso ABM"})
    return {
        "schema": "applefleet/1", "collectedAt": DEMO_NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organisation": "contoso.example", "source": "demo",
        "apnsCertificate": {"expires": _ts(days=9)},
        "adeInstances": [{"id": "1", "name": "Contoso ABM", "serverName": "Contoso Jamf Pro",
                          "serverUuid": "6F1C2A70-0D1E-4C8B-9E1A-2B3C4D5E6F70", "tokenExpires": _ts(days=214)}],
        "vppLocations": [{"id": "1", "name": "Contoso Apps and Books", "locationName": "Contoso",
                          "tokenExpires": _ts(days=-3)}],
        "adeDevices": ade_devices,
        "devices": devices,
    }


def write_demo(folder: Path) -> tuple[Path, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "jamf_inventory.json"
    path.write_text(json.dumps(demo_inventory(), indent=1), encoding="utf-8")
    vip = folder / "vip.txt"
    vip.write_text("# Executives and board members: their devices are checked first (one username per line)\n"
                   + "\n".join(VIP_USERS) + "\n", encoding="utf-8")
    return path, vip
