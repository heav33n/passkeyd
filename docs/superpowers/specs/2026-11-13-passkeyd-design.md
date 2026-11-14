# passkeyd — Windows Hello–style passkeys on Linux, backed by Bitwarden

Date: 2026-11-13 · Status: draft for approval

## Intent

On Windows, clicking "Sign in with passkey" in any app pops up Windows Hello:
pick the account if there are several, touch the fingerprint sensor, done —
with Bitwarden as the passkey store. Linux has no such layer. The user wants
the same experience on Linux (CachyOS, KDE Plasma on Wayland), first for
Discord and its community clients (Legcord, Vesktop, Discord PTB), and
**without installing a per-client plugin or mod** — it should be as close to
universal as possible.

## How it works (decided, validated by a spike)

`passkeyd` is a user daemon that creates a **virtual FIDO2 USB security key**
through `/dev/uhid`. Every app that supports hardware security keys —
Chromium/Electron apps, browsers — sees it as a plugged-in key and talks
CTAP2 over HID to it. The daemon does what Windows Hello does itself:

1. Finds the Bitwarden passkeys matching the requested site (`rpId`).
2. If more than one, shows its own account picker; returns only the chosen one.
3. Verifies the fingerprint through fprintd.
4. Signs the assertion with the passkey's private key from Bitwarden.

**Spike results (2026-11-13, `spike/virtual_key.py`, in Legcord):**
- Electron's native WebAuthn with no key present hangs forever (it has no
  Chrome dialogs), which is why Discord's button does nothing today.
- With the virtual key present, Electron completed `makeCredential` and a
  **discoverable** `getAssertion` (empty allowList — Discord's flow) with no
  dialogs, *provided* the response sets CTAP 2.1 `userSelected` (response
  key `0x06` = true). Without it, Chromium wants its own account-confirmation
  dialog, which Electron lacks, and fails with `NotAllowedError`.
- Observed request sequence: `getInfo` → `getAssertion {1 rpId, 2 cdh, 5 {uv: true}}`.
- getInfo advertised: versions `["FIDO_2_0"]`, options `{rk, up, uv: true, plat: false}`,
  no clientPin → Chromium sends `uv: true` and needs no PIN UI.
- The allowList (non-discoverable) path was not validated (test had a typo); expected to work.

## Goals

- "Sign in with passkey" in Legcord, Vesktop and Discord PTB works with:
  account picker (only if >1 match) → fingerprint → logged in.
- Works unchanged in any other app that supports security keys.
- Uses the passkeys already stored in the user's Bitwarden vault.
- Never asks for the master password in normal use (see Unlock).
- Starts automatically with the desktop session.

## Non-goals (v1)

- **Creating new passkeys into Bitwarden** (`makeCredential`). v1 answers
  `makeCredential` with `CTAP2_ERR_OPERATION_DENIED` so apps fail cleanly;
  the user creates passkeys with the Bitwarden browser extension. Later version.
- CTAP1/U2F, PIN (clientPin), credential management, hmac-secret/PRF, large blobs.
- Algorithms other than ES256 (that's what Bitwarden generates).
- Other password managers.

## Anti-goals (failures even if it "works")

- Signing anything that sets the UP flag without a successful fingerprint match.
- The Bitwarden session key ever written to disk in plaintext or logged.
- Private keys ever written to disk by passkeyd (keep in memory only).
- Showing the picker/fingerprint prompt for silent `up: false` probes.
- Modifying the user's vault in v1 (read-only).

## Constraints / environment facts

- Kernel `CONFIG_UHID=m`; `/etc/modules-load.d/uhid.conf` loads it at boot;
  `/etc/udev/rules.d/60-passkeyd-uhid.rules` grants the seat user access via
  `uaccess`. Both already installed. The resulting hidraw node gets user access
  automatically from systemd's `60-fido-id.rules` (confirmed by the spike).
- Python 3 with `fido2` 2.2.1 (CBOR codec), `cryptography`, `dbus-python`,
  `secretstorage`, GTK4 available. `zenity` installed. Bitwarden CLI
  standalone binary at `~/.local/bin/bw`, logged in.
- Secret Service (`org.freedesktop.secrets`) is available on the session bus.
- fprintd with a Goodix MOC sensor; right index finger enrolled.

## Coexistence with other authenticators (decided)

The user has no physical security key or phone passkeys; Bitwarden is the
only passkey store, and in browsers the Bitwarden extension intercepts
WebAuthn before Chromium reaches hardware keys. So passkeyd **fails fast**:
no match → `CTAP2_ERR_NO_CREDENTIALS` immediately, `makeCredential` →
`CTAP2_ERR_OPERATION_DENIED` immediately, and the "touch to select" probe
(empty `pinUvAuthParam`) is answered immediately. This keeps Electron apps
from hanging. Known consequence: if a real security key is ever plugged in,
Chromium may end requests on passkeyd's instant "no" — revisit then.

## Unlock model (decided: keyring-backed)

- One-time `passkeyd setup`: prompts for the master password (zenity
  `--password`), runs `bw unlock --raw` with it (passed via env/stdin,
  never argv), stores the resulting `BW_SESSION` in the Secret Service
  (label "passkeyd Bitwarden session", attributes `{application: passkeyd}`).
- The daemon reads `BW_SESSION` from the keyring at start. The keyring is
  unlocked with the desktop login, so the user never types the master password
  in normal use. Trade-off accepted by the user: the vault key is protected only
  by the login keyring.
- If the session stops working (`bw` reports locked/invalid — e.g. after
  `bw lock`/`bw logout`), the daemon shows a desktop notification telling
  the user to run `passkeyd setup` (my call: no surprise password prompts
  popping up mid-login).

## Bitwarden data

- At start (and when a request finds no match, rate-limited to once per
  minute) the daemon runs `bw sync` then `bw list items` with the session and
  keeps **only** each item's `login.fido2Credentials` in memory (plus item name).
- Fields used per credential: `credentialId`, `keyValue` (PKCS8, base64url),
  `rpId`, `userHandle` (base64url), `userName`, `userDisplayName`, `counter`,
  `creationDate`, `discoverable`. Credential ID encoding: Bitwarden stores
  GUID-form IDs as a UUID string (wire bytes = the 16 raw UUID bytes) and
  other IDs as `b64.<base64url>`. **Builder must verify these against the
  real vault** with a key-only dump (no values printed) before relying on them.
- **Freshness (my call):** resync every 10 minutes in the background, and
  also on a request that finds no match (rate-limited to once a minute). If a
  sync reports the session locked/invalid, wipe the in-memory credentials
  immediately (a `bw lock`/`bw logout` stops signing within one sync).
  No wipe on screen lock — the keyring stays unlocked then anyway.
- Signature counter: report the stored counter unchanged (Bitwarden keeps 0); no write-back.
- authData flags on assertion: UP (if fingerprint succeeded), UV, plus BE and
  BS (0x08|0x10), matching how Bitwarden's own clients present synced passkeys.

## Request flow (getAssertion)

1. Filter in-memory credentials by `rpId` and, if present, allowList.
2. None → `CTAP2_ERR_NO_CREDENTIALS` (after one rate-limited resync attempt).
3. `options.up == false` → sign silently without UP (no UI), as CTAP requires.
4. More than one → picker (zenity list): columns user name, display name,
   vault item name, created date; title "Sign in to <rpId>". Cancel →
   `CTAP2_ERR_OPERATION_DENIED`.
5. Fingerprint: fprintd D-Bus (`Claim`, `VerifyStart("any")`, wait for
   `VerifyStatus`, `Release`). While waiting, show a small zenity/notification
   "Touch the fingerprint sensor to sign in to <rpId> as <user>". Up to 3
   tries; then `CTAP2_ERR_OPERATION_DENIED`.
6. While steps 4–5 run, send CTAPHID `KEEPALIVE` (status 2, UPNEEDED) every
   100 ms. A CTAPHID `CANCEL` from the app aborts the picker/fingerprint and
   returns `CTAP2_ERR_KEEPALIVE_CANCEL`.
7. Respond with credential, authData, signature, user `{id, name, displayName}`,
   and `userSelected: true` (key 6) whenever the allowList was empty.

## Structure (builder's call on details)

- `passkeyd` Python package: `uhid.py` (device), `ctaphid.py` (framing,
  channels, keepalive/cancel), `ctap2.py` (getInfo/getAssertion/makeCredential),
  `vault.py` (bw + keyring), `ui.py` (picker, prompts), `fingerprint.py` (fprintd).
- CLI: `passkeyd run`, `passkeyd setup`, `passkeyd status`.
- systemd **user** unit `passkeyd.service`, `WantedBy=graphical-session.target`.
- Tests: CTAP2 logic offline (as the spike's offline test does), plus a manual
  end-to-end checklist in Legcord, Vesktop and PTB.
- **Order of work (my call):** before the bulk of the build, re-run the spike
  in Vesktop and Discord PTB and check the allowList path, so client
  differences surface early. Then the first real milestone is signing in with
  a Bitwarden-created passkey via Discord's actual "Sign in with passkey"
  button. v1 target is all three clients; if one client misbehaves for reasons
  outside passkeyd, ship for the others and note it.

## Approaches considered

1. **Virtual FIDO2 key over uhid** — chosen. Universal; no app changes;
   validated in Electron by the spike.
2. **Per-client plugin overriding `navigator.credentials`** (Vencord/Equicord/
   Legcord native plugin) — rejected by the user: no plugins just to log in.
3. **credentialsd / XDG credentials portal** — the "proper" future, but no app
   calls it today.
4. Phone/QR hybrid — Electron has no QR dialog either.

## Left to the builder

Module layout details, logging format (never log secrets), exact zenity
wording, threading model, vendor/product IDs for the virtual device, packaging
(a `pyproject.toml` + `pipx`/venv or plain scripts).
