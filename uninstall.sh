#!/usr/bin/env bash
# pi-passport uninstaller — stops the hotspot and restores the previous configs.
# Packages (tor, hostapd, dnsmasq…) and SSH/sysctl hardening are left in place;
# pass --all to remove the hardening too.
set -Eeuo pipefail

ALL=0
[[ "${1:-}" == "--all" ]] && ALL=1
[[ $EUID -eq 0 ]] || { echo "run me with sudo" >&2; exit 1; }

ap_if="$(python3 -c 'import json; print(json.load(open("/etc/pi-passport/passport.json"))["ap_if"])' 2>/dev/null || true)"

systemctl disable --now hostapd.service dnsmasq.service pi-passport-net.service 2>/dev/null || true
systemctl disable --now pi-passport-firewall.service 2>/dev/null || true
nft delete table inet passport 2>/dev/null || true
nft delete table ip passport_nat 2>/dev/null || true

restore() { if [[ -e "$1.pre-passport" ]]; then mv -f "$1.pre-passport" "$1"; else rm -f "$1"; fi; }
restore /etc/hostapd/hostapd.conf
restore /etc/tor/torrc

rm -f /etc/systemd/system/pi-passport-{net,firewall}.service \
      /etc/dnsmasq.d/pi-passport.conf \
      /etc/tor/passport-country.conf \
      /etc/NetworkManager/conf.d/90-pi-passport.conf \
      /usr/local/bin/passport
for unit in tor@default hostapd dnsmasq; do
  rm -f "/etc/systemd/system/$unit.service.d/pi-passport.conf"
  rmdir "/etc/systemd/system/$unit.service.d" 2>/dev/null || true
done
rm -rf /etc/pi-passport

if [[ $ALL -eq 1 ]]; then
  rm -f /etc/sysctl.d/90-pi-passport.conf /etc/ssh/sshd_config.d/10-pi-passport.conf
  sysctl -q --system >/dev/null
  systemctl reload ssh 2>/dev/null || true
fi

systemctl daemon-reload
systemctl restart tor@default.service 2>/dev/null || true
if [[ -n "$ap_if" ]]; then
  systemctl reload NetworkManager 2>/dev/null || true
  nmcli device set "$ap_if" managed yes 2>/dev/null || true
fi
echo "pi-passport removed."
