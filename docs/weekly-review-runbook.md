# Weekly Apple fleet review · runbook

For the workplace or endpoint engineer who looks after the Macs, iPhones and iPads in Jamf Pro, and the
service owner who reads the result.

## When

- **Every Monday morning.** Work through `device_actions.csv` top to bottom; bring `review.md` to the team
  meeting.
- **The day before a board or executive meeting**, run it again and look only at the *VIP devices* section:
  an iPad that has not checked in for two weeks will not have the board papers app updated either.
- **Whenever the token calendar shows something under 30 days.** Book the renewal in your calendar the same
  day; the person who knows the Apple Account may be on holiday on the day it expires.

## Run it

```bash
export JAMF_CLIENT_SECRET='...'          # from your password manager, never on the command line
python -m applefleet export --url https://yourorg.jamfcloud.com --client-id <client-id> --out jamf_inventory.json
python -m applefleet report jamf_inventory.json --vip vip.txt --apns-expires 2027-03-01 --out 2026-10-19
```

The API client needs a role with read privileges only: Read Computers, Read Mobile Devices, Read Device
Enrollment Program Instances, Read Volume Purchasing Locations. The APNs expiry date is in Jamf Pro under
**Settings > Global > Push certificates**; type it once a year into the command (or a wrapper script).

Change the OS baseline when Apple releases a security update you want everyone on:
`--min-macos 26.0.1 --min-ios 26.0.1 --min-ipados 26.0.1`. Move the "oldest supported major" when Apple stops
shipping security fixes for a version: `--oldest-macos 15`.

## The three things that can break the whole fleet

### APNs push certificate: renew, never replace

Without a valid push certificate Jamf Pro cannot send a single command: no profiles, no app installs, no lock
or wipe. If someone **creates a new certificate** instead of renewing, the topic changes and **every enrolled
device has to be enrolled again**. That is the most expensive mistake in Apple device management.

1. Find out which **Apple Account** created the certificate. It should be a shared, team-owned account kept in
   the password manager, not a person's account. Note the certificate's topic shown in Jamf Pro: the portal
   lists certificates per Apple Account, and the topic tells you which one is yours.
2. In Jamf Pro: **Settings > Global > Push certificates**, open the certificate and choose **Renew**. Download
   the signing request (CSR), or let Jamf Pro sign it for you if offered.
3. Sign in to the Apple Push Certificates Portal (identity.apple.com) **with that same Apple Account**. Find the
   certificate with the matching topic and click **Renew** next to it. Do **not** use "Create a Certificate".
4. Upload the CSR, download the new `.pem`, and upload it to Jamf Pro to finish the renewal.
5. Check: the expiry date moved one year ahead and the topic is unchanged. Send an inventory update to a test
   device and confirm it answers.
6. Put the new expiry date in the team calendar with a 30-day reminder, and update the `--apns-expires` value.

If it already expired: still **renew** (with the same Apple Account) as soon as possible. Devices stay enrolled
but receive nothing until it is renewed.

### ADE server token (Apple Business Manager)

When it expires, Jamf Pro stops syncing with Apple Business Manager: new or wiped devices are not assigned to
your PreStage enrollment and come up without management.

1. In Jamf Pro: **Settings > Global > Automated Device Enrollment**, open the instance. Download the public
   key if Jamf Pro asks for it.
2. In Apple Business Manager: **Preferences > (your MDM server)**, then **Download token** (upload the public
   key first if you created a new key).
3. Back in Jamf Pro, upload the token to the **same instance** (Renew / upload service token). Do not create a
   second instance for the same MDM server: PreStages and device assignments stay with the old one.
4. Check the new expiry date and that the instance syncs (devices list refreshes).

If the token is valid but sync still fails, check whether Apple Business Manager is waiting for someone to
accept new terms and conditions.

### Apps and Books (VPP) content token

When it expires, apps assigned through Jamf Pro stop installing and stop updating, and new users get nothing.

1. In Apple Business Manager: **Preferences > Payments and billing**, download the content (server) token for
   the location.
2. In Jamf Pro: **Settings > Global > Volume purchasing**, open the **existing location** and upload the new
   token there (Renew). Creating a new location instead leaves the apps and licences on the old one.
3. Check the expiry date and run a sync; confirm an app assignment still installs on a test device.

## What to do with each critical finding

| Finding | Same day |
|---|---|
| APNs push certificate under 14 days | Renew it today, following the steps above. |
| ADE or VPP token under 14 days or expired | Renew in place, following the steps above. |
| macOS / iOS / iPadOS on an unsupported major | Upgrade if the hardware supports it; otherwise plan the replacement and keep the device away from sensitive data until then. |
| FileVault off | Scope the FileVault profile to the Mac, ask the user to log out and in, confirm the personal recovery key appears in Jamf Pro. |
| SIP disabled | Ask the user why. Re-enable from recovery (`csrutil enable`). A developer who needs it off needs a documented exception, not a quiet change. |
| iPhone or iPad without passcode | Contact the user; scope the passcode profile and a compliance rule so access to company apps depends on it. |
| Not seen for more than 45 days | Contact the user or their manager. Lost: Lost Mode or remote wipe. Returned or in a drawer: recover it, wipe it, and update the record. |
| Storage under 5% | Ask the user to free space today: updates will fail until they do. |
| Any finding marked **(VIP)** | Same as above, but before the next executive or board meeting. Arrange a time with the assistant, bring a spare device if the fix needs a wipe. |

## Warnings to clear during the week

Below-minimum OS versions (push the update with a deadline), missing bootstrap tokens (they block MDM software
updates on Apple silicon), missing FileVault recovery keys (reissue), Gatekeeper and firewall off (enforce by
profile), unsupervised or hand-enrolled devices (re-enroll through ADE at the next reset), devices assigned in
ABM but never enrolled, warranties ending in the next 60 days (AppleCare can only be extended before it lapses).

## What the audit does not do

It does not change anything in Jamf Pro or Apple Business Manager, does not read installed apps or
configuration profiles, and does not replace smart groups and compliance rules: it is the weekly look across
all of them.
