#!/usr/bin/env bash
# pi-passport installer — turns a Raspberry Pi into a Wi-Fi hotspot whose
# traffic exits through Tor in the country you choose.
#
#   sudo ./install.sh [--country jp] [--ssid Passport] [options]
#
# Safe to re-run: every step is idempotent. Run with --help for options.
set -Eeuo pipefail
umask 077

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES="$REPO_DIR/templates"
ETC_DIR=/etc/pi-passport

COUNTRY=any
SSID=Passport
AP_IF=""
WIFI_REGION=""
CHANNEL=6
SECURITY=wpa3
NEW_PASSPHRASE=0
AP_ADDR=192.168.77.1
DHCP_START=192.168.77.10
DHCP_END=192.168.77.200

if [[ -t 1 ]]; then
  C_B=$'\e[1m' C_G=$'\e[32m' C_Y=$'\e[33m' C_R=$'\e[31m' C_C=$'\e[36m' C_0=$'\e[0m'
else
  C_B="" C_G="" C_Y="" C_R="" C_C="" C_0=""
fi
step() { printf '\n%s==>%s %s%s%s\n' "$C_C" "$C_0" "$C_B" "$*" "$C_0"; }
ok()   { printf '  %s✔%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }
trap 'die "failed at line $LINENO: $BASH_COMMAND"' ERR

usage() {
  cat <<EOF
Usage: sudo ./install.sh [options]

  --country CODE       Exit country, e.g. jp, de, "Japan", or "any" (default: any)
  --ssid NAME          Hotspot name (default: Passport)
  --ap-if IFACE        Radio to broadcast the hotspot on (default: auto-detect
                       a USB Wi-Fi adapter, or onboard Wi-Fi if you use Ethernet)
  --wifi-region CC     Where the Pi physically is, for legal radio channels
                       (default: read from the system)
  --channel N          2.4 GHz channel 1-13 (default: 6)
  --security MODE      wpa3 (default) or wpa2-wpa3 for older devices
  --new-passphrase     Generate a fresh hotspot password
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --country)        COUNTRY="${2:?}"; shift 2 ;;
    --ssid)           SSID="${2:?}"; shift 2 ;;
    --ap-if)          AP_IF="${2:?}"; shift 2 ;;
    --wifi-region)    WIFI_REGION="${2:?}"; shift 2 ;;
    --channel)        CHANNEL="${2:?}"; shift 2 ;;
    --security)       SECURITY="${2:?}"; shift 2 ;;
    --new-passphrase) NEW_PASSPHRASE=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                usage >&2; die "unknown option: $1" ;;
  esac
done

# --------------------------------------------------------------------------
step "Checking the system"

[[ $EUID -eq 0 ]] || die "run me with sudo: sudo ./install.sh"
# shellcheck source=/dev/null
. /etc/os-release
[[ "${ID:-}" == "debian" || "${ID:-}" == "raspbian" || "${ID_LIKE:-}" == *debian* ]] \
  || die "needs Raspberry Pi OS / Debian (found ${PRETTY_NAME:-unknown})"
[[ "${VERSION_ID%%.*}" -ge 12 ]] 2>/dev/null \
  || die "needs Raspberry Pi OS Bookworm (12) or newer (found ${PRETTY_NAME:-unknown})"
ok "$PRETTY_NAME"

[[ "$CHANNEL" =~ ^([1-9]|1[0-3])$ ]] || die "--channel must be 1-13"
[[ "$SECURITY" == wpa3 || "$SECURITY" == wpa2-wpa3 ]] || die "--security must be wpa3 or wpa2-wpa3"
ssid_bytes=$(printf '%s' "$SSID" | wc -c)
(( ssid_bytes >= 1 && ssid_bytes <= 32 )) || die "--ssid must be 1-32 bytes"
[[ "$SSID" != *[[:cntrl:]]* ]] || die "--ssid must not contain control characters"

UP_IF="$(ip -4 route show default | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
[[ -n "$UP_IF" ]] || die "no internet connection found. Connect the Pi to Wi-Fi or Ethernet first."
ok "internet via $UP_IF"

driver_of() { basename "$(readlink -f "/sys/class/net/$1/device/driver" 2>/dev/null)" 2>/dev/null || true; }

if [[ -z "$AP_IF" ]]; then
  # Prefer a USB adapter (anything that isn't the onboard brcmfmac chip),
  # otherwise the onboard radio when the Pi is online via Ethernet.
  for dev in /sys/class/net/*; do
    i="${dev##*/}"
    [[ -d "$dev/wireless" && "$i" != "$UP_IF" ]] || continue
    if [[ "$(driver_of "$i")" != brcmfmac ]]; then AP_IF="$i"; break; fi
    [[ -z "$AP_IF" ]] && AP_IF="$i"
  done
fi
[[ -n "$AP_IF" ]] || die "no spare Wi-Fi radio for the hotspot. Plug in a USB Wi-Fi adapter
       (one that supports AP mode), or connect the Pi with Ethernet."
[[ -d "/sys/class/net/$AP_IF/wireless" ]] || die "$AP_IF is not a Wi-Fi interface"
[[ "$AP_IF" != "$UP_IF" ]] || die "$AP_IF is the Pi's internet connection; pick a different radio"

if [[ "$SECURITY" == wpa3 && "$(driver_of "$AP_IF")" == brcmfmac ]]; then
  warn "the onboard radio can't do WPA3 as a hotspot; using WPA2/WPA3 mode"
  SECURITY=wpa2-wpa3
fi
ok "hotspot radio: $AP_IF ($(driver_of "$AP_IF"))"

if [[ -z "$WIFI_REGION" ]]; then
  WIFI_REGION="$(iw reg get 2>/dev/null | awk '/^country/ {sub(":","",$2); print $2; exit}')"
  if [[ -z "$WIFI_REGION" || "$WIFI_REGION" == 00 ]] && command -v raspi-config >/dev/null; then
    WIFI_REGION="$(raspi-config nonint get_wifi_country 2>/dev/null || true)"
  fi
fi
WIFI_REGION="${WIFI_REGION^^}"
[[ "$WIFI_REGION" =~ ^[A-Z]{2}$ && "$WIFI_REGION" != 00 ]] \
  || die "couldn't tell which country the Pi is in. Pass --wifi-region, e.g. --wifi-region US"
ok "Wi-Fi region: $WIFI_REGION"

# --------------------------------------------------------------------------
step "Installing packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  tor hostapd dnsmasq nftables iw curl python3 qrencode unattended-upgrades >/dev/null
ok "tor $(dpkg-query -W -f='${Version}' tor), hostapd, dnsmasq, nftables"

# --------------------------------------------------------------------------
step "Writing configuration"

install -d -m 0700 "$ETC_DIR"

if [[ -s "$ETC_DIR/ap.secret" && $NEW_PASSPHRASE -eq 0 ]]; then
  PASSPHRASE="$(<"$ETC_DIR/ap.secret")"
  ok "kept existing hotspot password"
else
  PASSPHRASE="$(python3 -c 'import secrets
a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
print("".join(secrets.choice(a) for _ in range(24)))')"
  printf '%s\n' "$PASSPHRASE" >"$ETC_DIR/ap.secret"
  ok "generated a new 24-character hotspot password"
fi

if [[ "$SECURITY" == wpa3 ]]; then KEY_MGMT=SAE; IEEE80211W=2
else KEY_MGMT="WPA-PSK SAE"; IEEE80211W=1; fi

ADMIN_USER="${SUDO_USER:-}"
export AP_IF AP_ADDR SSID PASSPHRASE WIFI_REGION CHANNEL KEY_MGMT IEEE80211W \
       DHCP_START DHCP_END ADMIN_USER

# render TEMPLATE DEST MODE — substitute {{VARS}} from the environment.
render() {
  local tmp
  tmp="$(mktemp "$(dirname "$2")/.passport.XXXXXX")"
  python3 - "$TEMPLATES/$1" "$tmp" <<'PY'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
def sub(m):
    value = os.environ.get(m.group(1))
    if value is None:
        sys.exit(f"template {src}: {m.group(1)} is not set")
    if "\n" in value:
        sys.exit(f"template {src}: {m.group(1)} contains a newline")
    return value
open(dst, "w", encoding="utf-8").write(re.sub(r"\{\{([A-Z0-9_]+)\}\}", sub, text))
PY
  chmod "$3" "$tmp"
  mv -f "$tmp" "$2"
}

backup_once() { [[ -e "$1" && ! -e "$1.pre-passport" ]] && cp -a "$1" "$1.pre-passport"; return 0; }

render firewall.nft "$ETC_DIR/firewall.nft" 0600
SECURITY="$SECURITY" UP_IF="$UP_IF" python3 - "$ETC_DIR/passport.json" <<'PY'
import json, os, sys
keys = ["SSID", "SECURITY", "AP_IF", "UP_IF", "AP_ADDR", "WIFI_REGION", "CHANNEL"]
json.dump({k.lower(): os.environ[k] for k in keys}, open(sys.argv[1], "w"), indent=2)
PY
chmod 0600 "$ETC_DIR/passport.json"

backup_once /etc/hostapd/hostapd.conf
render hostapd.conf /etc/hostapd/hostapd.conf 0600

install -d -m 0755 /etc/dnsmasq.d
render dnsmasq.conf /etc/dnsmasq.d/pi-passport.conf 0644

backup_once /etc/tor/torrc
render torrc /etc/tor/torrc 0644

render sysctl.conf /etc/sysctl.d/90-pi-passport.conf 0644
sysctl -q --system >/dev/null

if [[ -d /etc/NetworkManager/conf.d ]]; then
  render nm-unmanaged.conf /etc/NetworkManager/conf.d/90-pi-passport.conf 0644
  nmcli device set "$AP_IF" managed no 2>/dev/null || true
  systemctl reload NetworkManager 2>/dev/null || true
fi

render pi-passport-firewall.service /etc/systemd/system/pi-passport-firewall.service 0644
render pi-passport-net.service      /etc/systemd/system/pi-passport-net.service 0644
for unit in tor@default hostapd dnsmasq; do
  install -d -m 0755 "/etc/systemd/system/$unit.service.d"
  render service-override.conf "/etc/systemd/system/$unit.service.d/pi-passport.conf" 0644
done

install -m 0755 "$REPO_DIR/src/passport.py" /usr/local/bin/passport
ok "configuration written"

# --------------------------------------------------------------------------
step "Hardening the Pi"

cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
chmod 0644 /etc/apt/apt.conf.d/20auto-upgrades
ok "automatic security updates on"

for unit in bluetooth.service hciuart.service; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
done
ok "Bluetooth off"

keys_file=""
[[ -n "$ADMIN_USER" ]] && keys_file="$(getent passwd "$ADMIN_USER" | cut -d: -f6)/.ssh/authorized_keys"
if [[ -n "$keys_file" && -s "$keys_file" ]]; then
  render sshd.conf /etc/ssh/sshd_config.d/10-pi-passport.conf 0644
  if ! sshd -t; then
    rm -f /etc/ssh/sshd_config.d/10-pi-passport.conf
    die "SSH config check failed; left SSH unchanged"
  fi
  systemctl reload ssh
  ok "SSH: keys only, passwords disabled, only '$ADMIN_USER' may log in"
else
  warn "SSH still accepts passwords. Add your key from your computer, then re-run me:"
  warn "    ssh-copy-id ${ADMIN_USER:-you}@$(hostname).local"
fi

# --------------------------------------------------------------------------
step "Starting services"

systemctl daemon-reload
systemctl enable --now pi-passport-firewall.service >/dev/null
systemctl reload pi-passport-firewall.service
ok "firewall loaded (default deny, no routing)"

systemctl enable pi-passport-net.service >/dev/null
systemctl restart pi-passport-net.service

/usr/local/bin/passport set "$COUNTRY" --no-wait

systemctl unmask hostapd.service >/dev/null 2>&1 || true
systemctl enable tor@default.service hostapd.service dnsmasq.service >/dev/null 2>&1
systemctl restart tor@default.service dnsmasq.service

start_hostapd() { systemctl restart hostapd.service && sleep 3 && systemctl is-active --quiet hostapd.service; }
if ! start_hostapd; then
  if [[ "$SECURITY" == wpa3 ]]; then
    warn "$AP_IF refused WPA3-only mode; falling back to WPA2/WPA3"
    SECURITY=wpa2-wpa3 KEY_MGMT="WPA-PSK SAE" IEEE80211W=1
    export SECURITY KEY_MGMT IEEE80211W
    render hostapd.conf /etc/hostapd/hostapd.conf 0600
    python3 - "$ETC_DIR/passport.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["security"] = "wpa2-wpa3"
json.dump(d, open(p, "w"), indent=2)
PY
    start_hostapd || die "hostapd won't start on $AP_IF. See: journalctl -u hostapd -n 50"
  else
    die "hostapd won't start on $AP_IF. Does the adapter support AP mode? See: journalctl -u hostapd -n 50"
  fi
fi
ok "hotspot '$SSID' is up on $AP_IF"

printf '  … waiting for Tor to connect'
for _ in $(seq 1 90); do
  if passport status --quiet 2>/dev/null; then break; fi
  printf '.'; sleep 2
done
echo

# --------------------------------------------------------------------------
step "Done"
passport wifi
echo
echo "  Next:"
echo "    sudo passport status --check   # where does the web think I am?"
echo "    sudo passport set japan        # change country (any name or code)"
echo "    sudo passport list             # countries with Tor exits right now"
echo "    sudo passport doctor           # run the security self-check"
