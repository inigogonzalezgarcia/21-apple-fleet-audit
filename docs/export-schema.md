# Export schema (`applefleet/1`)

`python -m applefleet report` reads one JSON file. `python -m applefleet export` writes it from the Jamf Pro API;
`python -m applefleet demo` writes a fictional one to `sample_data/jamf_inventory.json`. You can also build it
from another source (a different MDM, a CSV) as long as it follows this shape.

**Rule for every field:** `null` or missing means "not collected". The check that needs it is skipped, never
guessed. A Mac with `"sipEnabled": null` gets no SIP finding; a Mac with `"sipEnabled": false` does.

Dates are ISO 8601: `2026-10-19`, `2026-10-19T07:00:00Z` or with milliseconds and offset. Times without a zone
are read as UTC.

## Top level

| Field | Type | Meaning | Jamf Pro API source |
|---|---|---|---|
| `schema` | string | `applefleet/1` | |
| `collectedAt` | date-time | When the export ran. All "days ago" and "days left" are counted from here. | |
| `organisation` | string | Label for the report. | `--organisation` or the Jamf Pro host name |
| `source` | string | Free text. | |
| `apnsCertificate` | object or null | `{"expires": "2027-03-01"}` | Not read from the API (not in every version): `--apns-expires` |
| `adeInstances` | list | Automated Device Enrollment (ABM) server tokens | `GET /api/v1/device-enrollments` |
| `vppLocations` | list | Apps and Books (VPP) content tokens | `GET /api/v1/volume-purchasing-locations` |
| `adeDevices` | list | Devices assigned to this MDM server in Apple Business Manager | `GET /api/v1/device-enrollments/{id}/devices` |
| `devices` | list | Computers and mobile devices | see below |

### `adeInstances[]`

| Field | Source |
|---|---|
| `id`, `name`, `serverName`, `serverUuid` | same names |
| `tokenExpires` | `tokenExpirationDate` |

Two instances with the same `serverUuid` are the same MDM server in ABM: when the newer one is valid, the
older one is not reported (it was renewed as a second instance; remove the old one when its PreStages moved).

### `vppLocations[]`

| Field | Source |
|---|---|
| `id`, `name`, `locationName` | same names |
| `tokenExpires` | `tokenExpiration` |

The Apple Account of the location is **not** exported.

### `adeDevices[]`

| Field | Source |
|---|---|
| `serial` | `serialNumber` |
| `model`, `description`, `profileStatus` | same names (`profileStatus`: `EMPTY`, `ASSIGNED`, `PUSHED`, `REMOVED`) |
| `assignedAt` | `deviceAssignedDate`, else `profileAssignTime` |
| `instance` | name of the ADE instance |

A serial here that matches no record in `devices` is reported as "assigned in ABM but never enrolled".

## `devices[]`

One object per computer or mobile device.

| Field | Type | Meaning | Computers (`/api/v1/computers-inventory`) | Mobile (`/api/v2/mobile-devices/detail`) |
|---|---|---|---|---|
| `id` | string | Jamf Pro ID | `id` | `mobileDeviceId` (per-device detail: `id`) |
| `name` | string | Device name | `general.name` | `general.displayName` (`name`) |
| `serial` | string | Serial number | `hardware.serialNumber` | `hardware.serialNumber` (`serialNumber`) |
| `platform` | string | `macOS`, `iOS` or `iPadOS` | always `macOS` | from `hardware.modelIdentifier` / model: `iPad…` = iPadOS, `iPhone…` = iOS |
| `model` | string | Marketing model | `hardware.model` | `hardware.model` (`ios.model`) |
| `osVersion` | string | e.g. `26.0.1` | `operatingSystem.version` | `general.osVersion` (`osVersion`) |
| `managed` | bool | `false` = inventory record only | `general.remoteManagement.managed` | `general.managed` (`managed`) |
| `supervised` | bool | | `general.supervised` | `general.supervised` (`ios.supervised`) |
| `enrolledViaAde` | bool | Enrolled through ADE | `general.enrolledViaAutomatedDeviceEnrollment` | same field if present, else `general.enrollmentMethodPrestage` (present but null = `false`) |
| `userApprovedMdm` | bool | Macs only | `general.userApprovedMdm` | null |
| `appleSilicon` | bool | Macs only | `hardware.appleSilicon`, else `processorArchitecture` = `arm64` | null |
| `lastContact` | date-time | Last check-in | `general.lastContactTime` | null |
| `lastInventory` | date-time | Last inventory update | `general.reportDate` | `general.lastInventoryUpdateDate` (`lastInventoryUpdateTimestamp`) |
| `username`, `realName` | string | Assigned user | `userAndLocation.username`, `.realname` | `userAndLocation.username`, `.realName` (`location.*`) |
| `fileVaultEnabled` | bool | | `diskEncryption.bootPartitionEncryptionDetails.partitionFileVault2State` (`ENCRYPTED`/`ENCRYPTING` = true, `UNENCRYPTED`/`DECRYPTING` = false), else `operatingSystem.fileVault2Status` | null |
| `recoveryKeyEscrowed` | bool | Valid personal recovery key in Jamf Pro | `diskEncryption.individualRecoveryKeyValidityStatus`: `VALID` = true, `INVALID`/`UNKNOWN` = false | null |
| `sipEnabled` | bool | | `security.sipStatus` (`ENABLED`/`DISABLED`, `NOT_COLLECTED` = null) | null |
| `gatekeeperEnabled` | bool | | `security.gatekeeperStatus` (`DISABLED` = false) | null |
| `firewallEnabled` | bool | | `security.firewallEnabled` | null |
| `bootstrapTokenEscrowed` | bool | | `security.bootstrapTokenEscrowedStatus` (`ESCROWED`/`NOT_ESCROWED`, `NOT_SUPPORTED` = null) | null |
| `passcodePresent` | bool | Mobile only | null | `security.passcodePresent` (`ios.security.passcodePresent`) |
| `storageTotalMb`, `storageFreeMb` | int | Boot volume | `storage.disks[].partitions[]` with `partitionType` `BOOT`; free from `storage.bootDriveAvailableSpaceMegabytes` | `hardware.capacityMb`, `hardware.availableSpaceMb` (`ios.capacityMb`, `ios.availableMb`) |
| `warrantyEnds` | date | Warranty or AppleCare end | `purchasing.warrantyDate` | `purchasing.warrantyExpiresDate` |

Names in brackets are the per-device `GET /api/v2/mobile-devices/{id}/detail` shape, used when the paged
`/detail` endpoint is not available in your Jamf Pro version.

These field names come from the public Jamf Pro API reference and are read defensively. They have not been
checked against a live Jamf Pro instance yet: if a value is always `null` in your export, look at the raw API
response for that section and adjust `applefleet/jamf.py`.

## VIP list (`--vip`)

Plain text, one Jamf Pro username per line (the `username` field above). Blank lines and `#` comments are
ignored; case does not matter.

```text
# Executive committee and board
e.navarro
j.whitfield
```
