"""Unit tests for the passport CLI. Run: python3 -m unittest discover tests"""

import importlib.util
import os
import re
import shutil
import socket
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

spec = importlib.util.spec_from_file_location("passport", ROOT / "src" / "passport.py")
passport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(passport)

NAMES = passport.load_country_names(FIXTURES / "iso3166.tab")


class CountryTests(unittest.TestCase):
    def test_loads_table(self):
        self.assertEqual(NAMES["jp"], "Japan")
        self.assertEqual(len(NAMES), 8)

    def test_resolves_codes_names_and_aliases(self):
        cases = {"jp": "jp", "JP": "jp", "Japan": "jp", " japan ": "jp",
                 "uk": "gb", "USA": "us", "united states": "us",
                 "germ": "de", "any": "any", "Fastest": "any"}
        for query, expected in cases.items():
            with self.subTest(query=query):
                self.assertEqual(passport.resolve_country(query, NAMES), expected)

    def test_rejects_unknown_and_ambiguous(self):
        for query in ("zz", "Atlantis", "korea (n", "ExitNodes {us}"):
            with self.subTest(query=query):
                if query == "korea (n":
                    self.assertEqual(passport.resolve_country(query, NAMES), "kp")
                    continue
                with self.assertRaises(passport.PassportError):
                    passport.resolve_country(query, NAMES)
        with self.assertRaisesRegex(passport.PassportError, "could mean"):
            passport.resolve_country("korea (", NAMES)

    def test_without_table_accepts_any_two_letter_code(self):
        self.assertEqual(passport.resolve_country("se", {}), "se")

    def test_flag(self):
        self.assertEqual(passport.flag("jp"), "\U0001F1EF\U0001F1F5")
        self.assertEqual(passport.flag("??"), "🌐")


class CountryConfTests(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "country.conf"
            for cc in ("jp", "any"):
                passport.write_atomic(path, passport.render_country_conf(cc))
                self.assertEqual(passport.read_configured_country(path), cc)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_strict_nodes_fail_closed(self):
        self.assertIn("StrictNodes 1", passport.render_country_conf("de"))

    def test_refuses_injection(self):
        for bad in ("jp}\nExitNodes {us", "j", "JP ", "../x"):
            with self.subTest(bad=bad), self.assertRaises(passport.PassportError):
                passport.render_country_conf(bad)

    def test_missing_file_means_any(self):
        self.assertEqual(passport.read_configured_country(Path("/nonexistent")), "any")


def reader(lines):
    it = iter(lines)
    return lambda: next(it)


class ControlProtocolTests(unittest.TestCase):
    def test_single_and_multi_line(self):
        reply = passport.parse_reply(reader(["250-version=0.4.8.12", "250 OK"]))
        self.assertEqual(passport.reply_to_dict(reply), {"version": "0.4.8.12"})

    def test_data_block_with_dot_escape(self):
        reply = passport.parse_reply(reader(
            ["250+ns/all=", "r a b", "..dotted", ".", "250 OK"]))
        self.assertEqual(passport.reply_to_dict(reply)["ns/all"], "r a b\n.dotted")

    def test_error_reply_raises(self):
        with self.assertRaisesRegex(passport.PassportError, "552"):
            passport.parse_reply(reader(['552 Unrecognized key "nope"']))

    def test_garbage_raises(self):
        with self.assertRaises(passport.PassportError):
            passport.parse_reply(reader(["hello"]))


NS_ALL = """\
r ExitOne AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-10-16 12:00:00 198.51.100.7 443 0
s Exit Fast Running Stable Valid
r Guardy BBBBBBBBBBBBBBBBBBBBBBBBBBB 2026-10-16 12:00:00 203.0.113.9 9001 0
s Fast Guard Running Stable Valid
r Naughty CCCCCCCCCCCCCCCCCCCCCCCCCCC 2026-10-16 12:00:00 192.0.2.44 443 0
s BadExit Exit Fast Running Valid
"""

CIRCUITS = """\
5 BUILT $AAAA~g1,$BBBB~m1,$CCCC~exitA BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL
6 BUILT $AAAA~g1,$DDDD~m2,$EEEE~hs BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY PURPOSE=GENERAL
7 EXTENDED $AAAA~g1 PURPOSE=GENERAL
8 BUILT $AAAA~g1,$FFFF~m3,$CCCC~exitA PURPOSE=GENERAL
9 BUILT $AAAA~g1,$9999=exitB PURPOSE=CONFLUX_LINKED
10 BUILT $AAAA~g1,$1234~m4,$ABCD~exitC
"""


class ParserTests(unittest.TestCase):
    def test_router_status(self):
        entries = passport.parse_router_status(NS_ALL)
        self.assertEqual([e["nickname"] for e in entries], ["ExitOne", "Guardy", "Naughty"])
        self.assertEqual(passport.exit_ips(entries), ["198.51.100.7"])

    def test_circuit_exits(self):
        self.assertEqual(passport.parse_circuit_exits(CIRCUITS), ["CCCC", "ABCD"])

    def test_wifi_qr_escapes(self):
        self.assertEqual(passport.wifi_qr_payload('My;Net', 'p:a"ss\\', "wpa3"),
                         'WIFI:T:SAE;S:My\\;Net;P:p\\:a\\"ss\\\\;;')
        self.assertTrue(passport.wifi_qr_payload("x", "y", "wpa2-wpa3").startswith("WIFI:T:WPA;"))


class FakeTor(threading.Thread):
    """A tiny control-port server: checks the cookie, answers a few GETINFOs."""

    def __init__(self, path, cookie):
        super().__init__(daemon=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(1)
        self.cookie = cookie
        self.commands = []

    def run(self):
        try:
            self._serve()
        except (BrokenPipeError, ConnectionResetError):
            pass  # client hung up, e.g. after a failed AUTHENTICATE
        finally:
            self.server.close()

    def _serve(self):
        conn, _ = self.server.accept()
        with conn, conn.makefile("rb") as rfile:
            for raw in rfile:
                line = raw.decode().rstrip("\r\n")
                self.commands.append(line)
                if line.startswith("AUTHENTICATE"):
                    ok = line.split()[1] == self.cookie.hex()
                    conn.sendall(b"250 OK\r\n" if ok else b"515 Bad authentication\r\n")
                elif line == "GETINFO status/bootstrap-phase":
                    conn.sendall(b'250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 '
                                 b'TAG=done SUMMARY="Done"\r\n250 OK\r\n')
                elif line.startswith("GETINFO ip-to-country/"):
                    out = [f"250-{k}=jp" for k in line.split()[1:]]
                    conn.sendall(("\r\n".join(out) + "\r\n250 OK\r\n").encode())
                elif line == "QUIT":
                    conn.sendall(b"250 closing connection\r\n")
                    return
                else:
                    conn.sendall(b"510 Unrecognized command\r\n")


class TorControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/tmp")
        self.sock_path = Path(self.tmp) / "control"
        self.cookie_path = Path(self.tmp) / "cookie"
        self.cookie = os.urandom(32)
        self.cookie_path.write_bytes(self.cookie)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_auth_bootstrap_and_countries(self):
        fake = FakeTor(self.sock_path, self.cookie)
        fake.start()
        with passport.TorControl(self.sock_path, self.cookie_path, timeout=5) as tor:
            self.assertEqual(tor.bootstrap(), 100)
            self.assertEqual(tor.countries(["198.51.100.7", "198.51.100.7", "203.0.113.9"]),
                             {"198.51.100.7": "jp", "203.0.113.9": "jp"})
        fake.join(5)
        self.assertEqual(fake.commands[0], f"AUTHENTICATE {self.cookie.hex()}")

    def test_wrong_cookie_is_rejected(self):
        fake = FakeTor(self.sock_path, b"right")
        fake.start()
        with self.assertRaisesRegex(passport.PassportError, "515"):
            with passport.TorControl(self.sock_path, self.cookie_path, timeout=5):
                pass

    def test_missing_tor_is_friendly(self):
        with self.assertRaisesRegex(passport.PassportError, "isn't running"):
            with passport.TorControl(self.sock_path, Path(self.tmp) / "nope"):
                pass

    def test_refuses_command_injection(self):
        fake = FakeTor(self.sock_path, self.cookie)
        fake.start()
        with passport.TorControl(self.sock_path, self.cookie_path, timeout=5) as tor:
            with self.assertRaises(passport.PassportError):
                tor.command("GETINFO version\r\nSIGNAL HALT")


class TemplateTests(unittest.TestCase):
    """Every {{VAR}} a template uses must be exported by install.sh."""

    def test_all_template_vars_are_exported(self):
        installer = (ROOT / "install.sh").read_text()
        joined = installer.replace("\\\n", " ")
        exported = set()
        for line in re.findall(r"^\s*export (.+)$", joined, re.M):
            exported |= {name for name in line.split() if re.fullmatch(r"[A-Z0-9_]+", name)}
        for template in (ROOT / "templates").iterdir():
            for var in re.findall(r"\{\{([A-Z0-9_]+)\}\}", template.read_text()):
                with self.subTest(template=template.name, var=var):
                    self.assertIn(var, exported)


if __name__ == "__main__":
    unittest.main()
