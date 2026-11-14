# passkeyd spike (throwaway)

Question: does Electron (Legcord/Vesktop/Discord) finish a WebAuthn request
when a security key answers, with no browser dialogs?

1. One-time: `sudo install -m644 60-passkeyd-uhid.rules /etc/udev/rules.d/ && sudo udevadm control --reload && sudo udevadm trigger --name-match=uhid`
2. Run: `python3 virtual_key.py` (leave it open)
3. Fully restart Legcord, open DevTools on discord.com, paste the test snippet.
4. Clean up afterwards: `rm spike_creds.json` (test keys, stored unencrypted).
