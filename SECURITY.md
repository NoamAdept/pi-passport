# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) instead.
I'll reply within a week.

## Design principles

1. **Fail closed.** The Pi never routes client packets (`ip_forward=0`, forward
   chain `policy drop`). Tor is the only way out, so a Tor failure means no
   connectivity, never a leak.
2. **Smallest possible attack surface.** From the hotspot, only DHCP (67/udp),
   Tor DNS (9053/udp) and Tor TransPort (9040/tcp) are reachable. There's no web
   UI, and there's no TCP control port.
3. **Firewall first.** The ruleset loads before `network-pre.target`, so there's
   no unprotected window during boot.
4. **Least privilege.** The Tor control socket and the hotspot secret are
   root-only. SSH is key-only, non-root and allow-listed.
5. **Stay patched.** `unattended-upgrades` applies Debian security fixes daily.

## Verifying a device

```bash
sudo passport doctor
```

```bash
sudo nft list ruleset
```

From a device on the hotspot, https://check.torproject.org should say
"Congratulations", and https://ipleak.net should show only the Tor exit, in the
country you chose, with no DNS or IPv6 leaks.

## Known, accepted risks

- **Tor exit relays can see unencrypted traffic.** Use HTTPS.
- **Hotspot clients can make DNS lookups and TCP connections through Tor.** That's
  the product. Anyone with the Wi-Fi password gets anonymized internet access,
  so treat the password like a house key (`sudo ./install.sh --new-passphrase`
  rotates it).
- **The Pi's own traffic** (OS updates, NTP, Tor itself) uses your normal
  connection. Only hotspot clients are routed through Tor.
- **Physical access.** Anyone holding the SD card can read it. Keep the Pi somewhere you trust.
