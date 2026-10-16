#!/usr/bin/env python3
"""passport — choose which country your pi-passport hotspot appears to be in.

Talks to Tor over its local, cookie-authenticated control socket. Standard
library only, so there is nothing extra to install or keep patched.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable

CONTROL_SOCKET = Path("/run/tor/control")
COOKIE_FILE = Path("/run/tor/control.authcookie")
COUNTRY_CONF = Path("/etc/tor/passport-country.conf")
STATE_FILE = Path("/etc/pi-passport/passport.json")
SECRET_FILE = Path("/etc/pi-passport/ap.secret")
ISO_TABLE = Path("/usr/share/zoneinfo/iso3166.tab")
TOR_UNIT = "tor@default.service"
SOCKS = "127.0.0.1:9050"
CHECK_URL = "https://check.torproject.org/api/ip"

UNITS = [
    "pi-passport-firewall.service",
    "pi-passport-net.service",
    "hostapd.service",
    "dnsmasq.service",
    TOR_UNIT,
]

ALIASES = {
    "uk": "gb", "britain": "gb", "great britain": "gb", "england": "gb",
    "usa": "us", "america": "us", "united states of america": "us",
    "holland": "nl", "korea": "kr", "south korea": "kr", "uae": "ae",
    "czechia": "cz", "the netherlands": "nl",
}
ANY = "any"
IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


class PassportError(Exception):
    """A problem worth showing to the user without a traceback."""


# --------------------------------------------------------------------------
# Output helpers

_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def bold(text: str) -> str:
    return _c("1", text)


def dim(text: str) -> str:
    return _c("2", text)


def good(text: str) -> str:
    return _c("32", text)


def bad(text: str) -> str:
    return _c("31", text)


def flag(cc: str) -> str:
    """Regional-indicator emoji for a two-letter country code."""
    if len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("a")) for ch in cc.lower())


# --------------------------------------------------------------------------
# Countries

def load_country_names(path: Path = ISO_TABLE) -> dict[str, str]:
    """Map lowercase ISO 3166 codes to names, using the system's tzdata table."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    names = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        code, _, name = line.partition("\t")
        if len(code) == 2:
            names[code.lower()] = name.strip()
    return names


def resolve_country(query: str, names: dict[str, str]) -> str:
    """Turn 'jp', 'JP', 'Japan' or 'any' into a lowercase code (or 'any')."""
    q = " ".join(query.strip().lower().split())
    if q in ("any", "fastest", "anywhere", "*"):
        return ANY
    if q in ALIASES:
        return ALIASES[q]
    if re.fullmatch(r"[a-z]{2}", q):
        if names and q not in names:
            raise PassportError(f"'{query}' is not a country code. Try: passport list")
        return q
    for code, name in names.items():
        if name.lower() == q:
            return code
    partial = sorted(code for code, name in names.items() if q in name.lower())
    if len(partial) == 1:
        return partial[0]
    if partial:
        options = ", ".join(f"{names[c]} ({c})" for c in partial[:6])
        raise PassportError(f"'{query}' could mean: {options}")
    raise PassportError(f"don't know a country called '{query}'. Try: passport list")


def country_label(cc: str, names: dict[str, str]) -> str:
    if cc == ANY:
        return "🌐 anywhere (fastest exits worldwide)"
    return f"{flag(cc)} {names.get(cc, cc.upper())} ({cc})"


def render_country_conf(cc: str) -> str:
    header = "# Managed by `passport set`. Do not edit by hand.\n"
    if cc == ANY:
        return header + "# No restriction: Tor picks exits anywhere in the world.\n"
    if not re.fullmatch(r"[a-z]{2}", cc):
        raise PassportError(f"refusing to write invalid country code {cc!r}")
    # StrictNodes: if no exit in this country is available, fail closed
    # rather than silently using another country.
    return header + f"ExitNodes {{{cc}}}\nStrictNodes 1\n"


def read_configured_country(path: Path = COUNTRY_CONF) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ANY
    match = re.search(r"^ExitNodes\s+\{([a-z]{2})\}", text, re.MULTILINE)
    return match.group(1) if match else ANY


def write_atomic(path: Path, text: str, mode: int = 0o644) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Tor control protocol (control-spec.txt, section 2.3)

Reply = list[tuple[str, "list[str] | None"]]


def parse_reply(readline: Callable[[], str]) -> Reply:
    """Read one reply: a list of (text, data_lines) per reply line.

    data_lines is set for '+' lines, which carry a dot-terminated data block.
    """
    out: Reply = []
    while True:
        line = readline()
        if len(line) < 4 or not line[:3].isdigit():
            raise PassportError(f"unexpected reply from Tor: {line!r}")
        status, sep, text = line[:3], line[3], line[4:]
        if not status.startswith("2"):
            raise PassportError(f"Tor said: {status} {text}")
        data = None
        if sep == "+":
            data = []
            while (chunk := readline()) != ".":
                data.append(chunk[1:] if chunk.startswith(".") else chunk)
        out.append((text, data))
        if sep == " ":
            return out


def reply_to_dict(reply: Reply) -> dict[str, str]:
    values = {}
    for text, data in reply:
        key, eq, value = text.partition("=")
        if eq:
            values[key] = "\n".join(data) if data is not None else value
    return values


class TorControl:
    def __init__(self, socket_path: Path = CONTROL_SOCKET,
                 cookie_path: Path = COOKIE_FILE, timeout: float = 30) -> None:
        self.socket_path = socket_path
        self.cookie_path = cookie_path
        self.timeout = timeout

    def __enter__(self) -> TorControl:
        try:
            cookie = self.cookie_path.read_bytes()
        except PermissionError:
            raise PassportError("permission denied reading Tor's cookie. Use sudo.") from None
        except OSError:
            raise PassportError(f"Tor isn't running. Check: systemctl status {TOR_UNIT}") from None
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect(str(self.socket_path))
        except OSError as exc:
            self.sock.close()
            raise PassportError(f"can't reach Tor's control socket: {exc}") from None
        self.rfile = self.sock.makefile("rb")
        try:
            self.command(f"AUTHENTICATE {cookie.hex()}")
        except BaseException:
            self.rfile.close()
            self.sock.close()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self.sock.sendall(b"QUIT\r\n")
        except OSError:
            pass
        self.rfile.close()
        self.sock.close()

    def _readline(self) -> str:
        raw = self.rfile.readline()
        if not raw:
            raise PassportError("Tor closed the control connection")
        return raw.decode("utf-8", "replace").rstrip("\r\n")

    def command(self, line: str) -> Reply:
        if "\r" in line or "\n" in line:
            raise PassportError("refusing to send a multi-line control command")
        self.sock.sendall(line.encode("ascii") + b"\r\n")
        return parse_reply(self._readline)

    def getinfo(self, *keys: str) -> dict[str, str]:
        return reply_to_dict(self.command("GETINFO " + " ".join(keys)))

    def bootstrap(self) -> int:
        phase = self.getinfo("status/bootstrap-phase")["status/bootstrap-phase"]
        match = re.search(r"PROGRESS=(\d+)", phase)
        return int(match.group(1)) if match else 0

    def countries(self, ips: Iterable[str], chunk: int = 200) -> dict[str, str]:
        ips = list(dict.fromkeys(ips))
        result = {}
        for i in range(0, len(ips), chunk):
            keys = [f"ip-to-country/{ip}" for ip in ips[i:i + chunk]]
            for key, cc in self.getinfo(*keys).items():
                result[key.split("/", 1)[1]] = cc.lower()
        return result

    def relays(self) -> list[dict]:
        return parse_router_status(self.getinfo("ns/all")["ns/all"])

    def relay_ip(self, fingerprint: str) -> str | None:
        key = f"ns/id/{fingerprint}"
        try:
            entries = parse_router_status(self.getinfo(key).get(key, ""))
        except PassportError:
            return None  # relay dropped out of the consensus since the circuit was built
        return entries[0]["ip"] if entries else None

    def live_exit_fingerprints(self) -> list[str]:
        return parse_circuit_exits(self.getinfo("circuit-status")["circuit-status"])

    def new_identity(self) -> None:
        self.command("SIGNAL NEWNYM")


def parse_router_status(text: str) -> list[dict]:
    """Parse 'r'/'s' lines from GETINFO ns/* into [{nickname, ip, flags}]."""
    entries: list[dict] = []
    for line in text.splitlines():
        if line.startswith("r "):
            tokens = line.split()
            ip = next((t for t in tokens[3:] if IPV4.fullmatch(t)), None)
            entries.append({"nickname": tokens[1], "ip": ip, "flags": set()})
        elif line.startswith("s ") and entries:
            entries[-1]["flags"] = set(line.split()[1:])
    return entries


def exit_ips(entries: Iterable[dict]) -> list[str]:
    return [e["ip"] for e in entries
            if e["ip"] and "Exit" in e["flags"] and "BadExit" not in e["flags"]]


def parse_circuit_exits(text: str) -> list[str]:
    """Fingerprints of the last hop of every built, general-purpose circuit."""
    fingerprints = []
    for line in text.splitlines():
        tokens = line.split()
        if len(tokens) < 3 or tokens[1] != "BUILT" or not tokens[2].startswith("$"):
            continue
        fields = dict(t.split("=", 1) for t in tokens[3:] if "=" in t)
        if fields.get("PURPOSE", "GENERAL") != "GENERAL":
            continue
        build_flags = fields.get("BUILD_FLAGS", "").split(",")
        if "IS_INTERNAL" in build_flags or "ONEHOP_TUNNEL" in build_flags:
            continue
        last_hop = tokens[2].split(",")[-1]
        fingerprints.append(re.split(r"[~=]", last_hop[1:], maxsplit=1)[0])
    return list(dict.fromkeys(fingerprints))


# --------------------------------------------------------------------------
# System helpers

def require_root() -> None:
    if os.geteuid() != 0:
        raise PassportError("this needs root. Run it with sudo.")


def unit_active(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", unit],
                          check=False).returncode == 0


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except PermissionError:
        raise PassportError("permission denied reading pi-passport settings. Use sudo.") from None
    except (OSError, ValueError):
        raise PassportError("pi-passport isn't installed. Run: sudo ./install.sh") from None


def check_via_tor(timeout: int = 45) -> dict:
    """Ask check.torproject.org, through Tor, which IP we appear to come from."""
    try:
        proc = subprocess.run(
            ["curl", "-fsS", "--max-time", str(timeout), "--socks5-hostname", SOCKS, CHECK_URL],
            capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise PassportError("curl is missing: sudo apt install curl") from None
    if proc.returncode != 0:
        raise PassportError(f"couldn't reach the internet through Tor ({proc.stderr.strip()})")
    try:
        return json.loads(proc.stdout)
    except ValueError:
        raise PassportError("check.torproject.org sent something unexpected") from None


def wifi_qr_payload(ssid: str, password: str, security: str) -> str:
    """Build a 'WIFI:' QR payload (ZXing format), escaping special characters."""
    def esc(value: str) -> str:
        return re.sub(r'([\\;,:"])', r"\\\1", value)
    kind = "SAE" if security == "wpa3" else "WPA"
    return f"WIFI:T:{kind};S:{esc(ssid)};P:{esc(password)};;"


# --------------------------------------------------------------------------
# Commands

def cmd_status(args: argparse.Namespace) -> int:
    with TorControl() as tor:
        progress = tor.bootstrap()
        if args.quiet:
            return 0 if progress == 100 else 1
        names = load_country_names()
        configured = read_configured_country()
        print(f"{bold('Configured exit')}  {country_label(configured, names)}")
        if progress < 100:
            print(f"{bold('Tor')}              connecting… {progress}%")
            return 1
        print(f"{bold('Tor')}              {good('connected')}")

        fingerprints = tor.live_exit_fingerprints()
        ips = [ip for ip in (tor.relay_ip(fp) for fp in fingerprints[:8]) if ip]
        countries = tor.countries(ips)
        live = Counter(countries.values())
        if live:
            shown = "  ".join(f"{flag(cc)} {cc}×{n}" for cc, n in live.most_common())
            print(f"{bold('Live circuits')}    {shown}")
        else:
            print(f"{bold('Live circuits')}    {dim('none yet (they appear once a device browses)')}")

        if args.check:
            result = check_via_tor()
            ip = result.get("IP", "?")
            cc = tor.countries([ip]).get(ip, "??")
            verdict = good("yes") if result.get("IsTor") else bad("NO")
            print(f"{bold('Seen by the web')}  {ip}  {flag(cc)} {names.get(cc, cc)}  (Tor: {verdict})")
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    require_root()
    names = load_country_names()
    cc = resolve_country(" ".join(args.country), names)
    tor_running = unit_active(TOR_UNIT)

    if cc != ANY and tor_running and not args.no_wait and not args.force:
        with TorControl() as tor:
            if tor.bootstrap() == 100:
                available = Counter(tor.countries(exit_ips(tor.relays())).values())
                if not available.get(cc):
                    raise PassportError(
                        f"Tor has no exit relays in {names.get(cc, cc)} right now, so nothing "
                        "would load. Pick another (passport list) or use --force.")

    write_atomic(COUNTRY_CONF, render_country_conf(cc))
    print(f"Exit country set to {country_label(cc, names)}")

    if not tor_running:
        return 0
    subprocess.run(["systemctl", "reload", TOR_UNIT], check=True)
    with TorControl() as tor:
        tor.new_identity()
    print(dim("New connections use the new country; open ones finish where they started."))

    if args.no_wait:
        return 0
    print(dim("Checking the new exit…"))
    time.sleep(1)
    result = check_via_tor()
    ip = result.get("IP", "?")
    with TorControl() as tor:
        seen = tor.countries([ip]).get(ip, "??")
    if cc != ANY and seen != cc:
        raise PassportError(f"expected {cc} but the web sees {ip} in {seen}. Try: sudo passport new")
    print(good(f"✔ The web now sees {ip}, in {flag(seen)} {names.get(seen, seen)}"))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    names = load_country_names()
    configured = read_configured_country()
    with TorControl() as tor:
        if tor.bootstrap() < 100:
            raise PassportError("Tor is still connecting. Try again in a minute.")
        counts = Counter(tor.countries(exit_ips(tor.relays())).values())
    counts.pop("??", None)
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if not args.all:
        rows = [r for r in rows if r[1] >= 3]
    width = max((len(names.get(cc, cc)) for cc, _ in rows), default=10)
    print(bold(f"{'':4}{'code':6}{'country':{width + 2}}exits"))
    for cc, n in rows:
        mark = good("  ← current") if cc == configured else ""
        print(f"{flag(cc):4}{cc:6}{names.get(cc, cc.upper()):{width + 2}}{n:>5}{mark}")
    if not args.all:
        print(dim("Countries with fewer than 3 exits are hidden (they're slow and fragile). "
                  "Show them with --all."))
    return 0


def cmd_new(args: argparse.Namespace) -> int:
    with TorControl() as tor:
        tor.new_identity()
    print("New circuits requested. New connections get a new exit IP.")
    return 0


def cmd_wifi(args: argparse.Namespace) -> int:
    require_root()
    state = load_state()
    password = SECRET_FILE.read_text(encoding="utf-8").strip()
    security = "WPA3" if state["security"] == "wpa3" else "WPA2/WPA3"
    print(f"  {bold('Hotspot')}   {state['ssid']}")
    print(f"  {bold('Password')}  {password}")
    print(f"  {bold('Security')}  {security}, devices isolated from each other")
    payload = wifi_qr_payload(state["ssid"], password, state["security"])
    try:
        subprocess.run(["qrencode", "-t", "ansiutf8", "-m", "2", payload], check=True)
        print(dim("  Scan with your phone's camera to join."))
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    require_root()
    state = load_state()
    ap_if = state["ap_if"]
    results: list[tuple[str, bool]] = []

    def check(label: str, passed: bool) -> None:
        results.append((label, passed))

    def read(path: str) -> str:
        try:
            return Path(path).read_text().strip()
        except OSError:
            return ""

    for unit in UNITS:
        check(f"{unit} is running", unit_active(unit))
    check("IPv4 forwarding is off (no route around Tor)",
          read("/proc/sys/net/ipv4/ip_forward") == "0")
    check("IPv6 forwarding is off", read("/proc/sys/net/ipv6/conf/all/forwarding") == "0")
    check(f"IPv6 disabled on hotspot {ap_if}",
          read(f"/proc/sys/net/ipv6/conf/{ap_if}/disable_ipv6") == "1")
    nft = subprocess.run(["nft", "list", "chain", "inet", "passport", "forward"],
                         capture_output=True, text=True, check=False)
    check("firewall loaded, forward policy is drop",
          nft.returncode == 0 and "policy drop" in nft.stdout)
    sshd = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False)
    check("SSH refuses passwords", "passwordauthentication no" in sshd.stdout.lower())
    check("SSH refuses root", "permitrootlogin no" in sshd.stdout.lower())
    check("automatic security updates enabled",
          'Unattended-Upgrade "1"' in read("/etc/apt/apt.conf.d/20auto-upgrades"))
    check("hotspot secret is private", (SECRET_FILE.stat().st_mode & 0o077) == 0
          if SECRET_FILE.exists() else False)
    try:
        with TorControl() as tor:
            check("Tor is connected", tor.bootstrap() == 100)
    except PassportError:
        check("Tor is connected", False)

    for label, passed in results:
        print(f"  {good('✔') if passed else bad('✘')} {label}")
    failed = sum(not passed for _, passed in results)
    print()
    print(good("All checks passed.") if not failed else bad(f"{failed} check(s) failed."))
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passport",
        description="Pick the country your Raspberry Pi hotspot appears to be in.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="show the configured and live exit country")
    p.add_argument("--check", action="store_true",
                   help="also confirm via check.torproject.org what the web sees")
    p.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("set", help="change the exit country (e.g. 'jp', 'Japan', 'any')")
    p.add_argument("country", nargs="+")
    p.add_argument("--no-wait", action="store_true", help="don't verify the new exit")
    p.add_argument("--force", action="store_true", help="skip the exit-availability check")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("list", help="countries where Tor exits are available now")
    p.add_argument("--all", action="store_true", help="include countries with very few exits")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("new", help="get a fresh exit IP in the same country")
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("wifi", help="show the hotspot name, password and a QR code")
    p.set_defaults(func=cmd_wifi)

    p = sub.add_parser("doctor", help="run the security self-check")
    p.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PassportError as exc:
        print(f"{bad('error:')} {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
