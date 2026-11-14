# passkeyd

**Windows Hello–style passkeys on Linux, backed by Bitwarden.**

Click "Sign in with passkey" in an app → pick the account (only if you have more
than one) → touch your fingerprint sensor → you're in.

passkeyd is a small user daemon that creates a **virtual FIDO2 USB security key**
(via `/dev/uhid`). Apps that support hardware security keys talk to it like a
YubiKey; it answers with the passkeys stored in your **Bitwarden** vault, after
checking your fingerprint with **fprintd**. No browser extension, no app plugins.

> **Why?** Electron apps such as Discord, Legcord or Vesktop have no WebAuthn UI
> on Linux and no Bitwarden extension, so "Sign in with passkey" just hangs
> forever. With passkeyd it works.

Tested with Discord's passwordless "Sign in with passkey" and security-key 2FA
in **Legcord** and **Discord PTB** on KDE Plasma (Wayland). Any Chromium/Electron
app that supports security keys should work the same way.

## How it works

```
App (Discord, Legcord, …) ── WebAuthn ──> Chromium FIDO stack
                                             │  CTAP2 over HID
                                             ▼
                               /dev/uhid virtual key  ←  passkeyd
                                             │
          ┌──────────────────────────────────┼──────────────────────────┐
          ▼                                  ▼                          ▼
  account picker (zenity)          fingerprint (fprintd)     Bitwarden vault (bw CLI)
  only if >1 passkey matches       3 attempts                passkeys kept in memory
```

- It **only signs in**: create new passkeys with the Bitwarden browser extension
  or app as usual. passkeyd never writes to your vault.
- Every sign-in needs your fingerprint. Silent "does this key exist?" probes never
  reveal your accounts.
- Private keys are kept in memory only. The Bitwarden session key is stored in your
  desktop keyring (KWallet / GNOME Keyring), which unlocks when you log in — so you
  type your master password once, during setup.

## Requirements

- Linux with `uhid` support (`CONFIG_UHID`, built in or as a module — true on all
  mainstream distro kernels) and systemd
- A fingerprint reader supported by **fprintd**, with a finger enrolled
- A desktop with a Secret Service keyring (KDE Plasma's KWallet or GNOME Keyring)
- Python 3.10+ with `fido2`, `cryptography`, `secretstorage`
- `zenity` (dialogs) and `notify-send` (notifications)
- The **Bitwarden CLI** (`bw`), logged in to your account
- Your passkeys saved in Bitwarden

## Setup

### 1. Install dependencies

**Arch / CachyOS / Manjaro**
```sh
sudo pacman -S --needed python-fido2 python-cryptography python-secretstorage zenity libnotify fprintd
```

**Fedora**
```sh
sudo dnf install python3-fido2 python3-cryptography python3-secretstorage zenity libnotify fprintd
```

**Debian / Ubuntu**
```sh
sudo apt install python3-fido2 python3-cryptography python3-secretstorage zenity libnotify-bin fprintd
```

### 2. Install the Bitwarden CLI

Use Bitwarden's standalone binary (no Node.js needed):
```sh
mkdir -p ~/.local/bin
cd /tmp && curl -L "https://bitwarden.com/download/?app=cli&platform=linux" -o bw.zip \
  && unzip -o bw.zip && install -m755 bw ~/.local/bin/bw && rm bw bw.zip
bw login
```
(If you self-host Bitwarden/Vaultwarden, run `bw config server https://your.server` before `bw login`.)

### 3. Enroll a fingerprint

Skip if you already use your fingerprint to log in.
```sh
fprintd-enroll
fprintd-verify      # touch the sensor; should print "verify-match"
```

### 4. Get passkeyd

The systemd unit expects the checkout at `~/passkeyd`:
```sh
git clone https://github.com/heav33n/passkeyd ~/passkeyd
cd ~/passkeyd
```

### 5. Let your user create the virtual key

This loads the `uhid` kernel module at every boot and gives the logged-in desktop
user access to `/dev/uhid`:
```sh
sudo install -m644 contrib/60-passkeyd-uhid.rules /etc/udev/rules.d/
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid
sudo udevadm control --reload
sudo udevadm trigger --action=change --subsystem-match=misc --sysname-match=uhid
getfacl -p /dev/uhid | grep "user:$USER"     # should show user:<you>:rw-
```
If `modprobe` says *Module uhid not found*, your kernel was updated since the last
boot: reboot and run these commands again.

### 6. Connect to Bitwarden

```sh
python3 -m passkeyd setup      # asks for your master password once
python3 -m passkeyd status     # should show: session in keyring: yes, passkeys loaded: N
```

### 7. Start the service

```sh
mkdir -p ~/.config/systemd/user
cp contrib/passkeyd.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now passkeyd
journalctl --user -u passkeyd -n 5     # "virtual security key ready", "loaded N passkeys"
```

It starts automatically with your desktop session from now on.

### 8. Try it

Restart the app you want to use (apps detect security keys at startup), log out,
and click **Sign in with passkey**. For 2FA, choose the security key / passkey
option.

## Everyday use

| Situation | What happens |
|---|---|
| One passkey for the site | Fingerprint prompt only |
| Several passkeys for the site | Account picker (user, name, vault item, creation date), then fingerprint |
| You cancel the picker or prompt | The app gets a clean "denied" and you can retry |
| Wrong finger 3 times | Sign-in refused, notification shown |
| Bitwarden is locked / logged out | Notification: run `cd ~/passkeyd && python3 -m passkeyd setup` |
| You just added a passkey in Bitwarden | The vault refreshes every 10 minutes, or in the background after a failed attempt — try again a few seconds later |

Commands:
- `python3 -m passkeyd status` — device access, keyring session, passkeys loaded
- `journalctl --user -u passkeyd -f` — live logs (no secrets, no usernames)
- `systemctl --user restart passkeyd` — reload everything

## Troubleshooting

- **Nothing happens / the app keeps waiting.** Restart the app after starting
  passkeyd. Make sure only **one** virtual or real security key is plugged in —
  two keys answering at once can make sign-ins fail.
- **"No access to /dev/uhid"** — redo step 5; check `lsmod | grep uhid`.
- **No dialogs appear when running as a service** — the service needs your
  graphical session's environment; it is started by `graphical-session.target`,
  which KDE Plasma and GNOME provide. Run `python3 -m passkeyd run` in a terminal
  to test outside systemd (stop the service first).
- **"Fingerprint not recognised" immediately** — another program may be holding
  the sensor (e.g. the lock screen); check `fprintd-verify` on its own.
- **`passkeys loaded: 0`** — run `bw sync` and check your passkeys exist in
  Bitwarden (`bw list items | grep fido2Credentials`).

## Limitations

- Sign-in only (no passkey creation), ES256/P-256 passkeys only (what Bitwarden
  creates).
- Browsers with the Bitwarden extension already handle passkeys themselves; the
  extension answers before hardware keys are asked.
- passkeyd answers "no" immediately for sites it has no passkey for, so it can get
  in the way of a **real** security key plugged in at the same time.

## Security notes

- The Bitwarden session key lives in your login keyring; anyone who can unlock
  your desktop session can use it. That is the same trust level as the keyring
  itself.
- `BW_SESSION` and your master password are only ever passed to `bw` through
  environment variables, never on the command line or in logs.
- Names shown in dialogs are sanitized, since sites and local apps choose them.

## Development

```sh
python3 -m unittest discover -s tests
```

Design notes: [`docs/superpowers/specs`](docs/superpowers/specs), implementation
plan: [`docs/superpowers/plans`](docs/superpowers/plans).

## License

MIT
