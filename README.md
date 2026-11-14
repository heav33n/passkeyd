# passkeyd

Windows Hello–style passkeys on Linux: a virtual FIDO2 USB security key that signs
logins with your **Bitwarden** passkeys after an account pick (if more than one)
and a **fingerprint** check. Works in any app that supports security keys —
Discord, Legcord, Vesktop, browsers — with no plugins.

## Install (one time)

```sh
sudo install -m644 contrib/60-passkeyd-uhid.rules /etc/udev/rules.d/
echo uhid | sudo tee /etc/modules-load.d/uhid.conf
sudo modprobe uhid && sudo udevadm trigger --action=change --subsystem-match=misc --sysname-match=uhid
python3 -m passkeyd setup          # asks for the Bitwarden master password once
cp contrib/passkeyd.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now passkeyd
```

Requirements: `bw` CLI logged in, fprintd with an enrolled finger, zenity, python3
with `fido2`, `cryptography`, `secretstorage`.

## Use

Click "Sign in with passkey". Pick the account if asked, touch the sensor.

- `python3 -m passkeyd status` — device access, keyring session, passkeys loaded
- `journalctl --user -u passkeyd -f` — logs (no secrets, no usernames)
- "Bitwarden is locked" notification → run `python3 -m passkeyd setup` again

## Security notes

The Bitwarden session key is stored in your desktop keyring (unlocked at login).
Private keys stay in memory. Every sign-in needs your fingerprint. v1 only signs in;
create new passkeys with the Bitwarden browser extension.
