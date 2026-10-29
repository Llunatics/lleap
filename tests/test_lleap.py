"""Test suite for lleap. Standard library only, fully offline.

The lab server runs on 127.0.0.1 in a thread, so integration tests prove
real behaviour: a server-side fetch of a canary URL, an open redirect, and
a refusing target — without touching the network.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lleap.cli import _parse_sets, cmd_lab  # noqa: E402
from lleap.lab import start_lab  # noqa: E402
from lleap.payloads import GROUPS, Payload, payloads_for  # noqa: E402
from lleap.scanner import (  # noqa: E402
    check_target_safety, classify, scan, scan_one, term_safe,
)


class TestCatalog(unittest.TestCase):
    def test_every_group_nonempty(self):
        for group in GROUPS:
            self.assertTrue(payloads_for((group,)), group)

    def test_no_payload_points_at_real_third_party(self):
        # Every payload host must be loopback, link-local, metadata, or the
        # obviously fake evil.example.com / trusted.example.com stand-ins.
        allowed = ("127.", "localhost", "169.254.", "100.100.",
                   "metadata.google.internal", "[::1]", "[fd00:ec2::254]",
                   "0.0.0.0", "2130706433", "0x7f000001", "017700000001",
                   "127.1", "evil.example.com", "trusted.example.com")
        for payload in payloads_for():
            value = payload.value
            if "://" not in value and not value.startswith("//"):
                continue  # scheme-relative / scheme-only values
            host = value.split("://", 1)[-1].split("/")[0].split("@")[-1]
            host = host.split("%")[0]
            if not host:
                continue  # scheme-only values such as file:///etc/passwd
            if host.startswith("["):
                host = host[1:].split("]")[0]
            else:
                host = host.split(":")[0]
            self.assertTrue(
                any(host.startswith(a) or host == a.strip("[]")
                    for a in allowed),
                f"unexpected host in payload: {value}",
            )

    def test_unknown_group_rejected(self):
        with self.assertRaises(ValueError):
            payloads_for(("nope",))


class TestClassify(unittest.TestCase):
    def test_lab_success_is_fetched(self):
        body = json.dumps({"lleap_lab": True,
                           "fetched_status": 200, "fetched_url": "x"})
        verdict, _ = classify(Payload("http://127.0.0.1/", "localhost", ""),
                              200, None, body)
        self.assertEqual(verdict, "FETCHED")

    def test_lab_json_without_marker_is_not_trusted(self):
        # Any JSON API can return a field named "fetched_status"; without
        # the lab marker it must not count as lab ground truth.
        body = json.dumps({"fetched_status": 200, "fetched_url": "x"})
        verdict, _ = classify(Payload("http://127.0.0.1/", "localhost", ""),
                              200, None, body)
        self.assertEqual(verdict, "UNCLEAR")

    def test_lab_failure_is_unclear(self):
        body = json.dumps({"fetched_status": None,
                           "fetch_error": "URLError: timed out"})
        verdict, _ = classify(Payload("http://127.0.0.1/", "localhost", ""),
                              200, None, body)
        self.assertEqual(verdict, "UNCLEAR")

    def test_blocked_keyword(self):
        verdict, _ = classify(Payload("http://127.0.0.1/", "localhost", ""),
                              403, None, "request blocked by filter")
        self.assertEqual(verdict, "BLOCKED")

    def test_open_redirect_absolute(self):
        payload = Payload("https://evil.example.com/", "redirect", "")
        verdict, _ = classify(payload, 302, "https://evil.example.com/", "")
        self.assertEqual(verdict, "OPEN-REDIRECT")

    def test_open_redirect_scheme_without_slashes(self):
        payload = Payload("https:evil.example.com", "redirect", "")
        verdict, _ = classify(payload, 302, "https:evil.example.com", "")
        self.assertEqual(verdict, "OPEN-REDIRECT")

    def test_redirect_host_case_and_trailing_dot(self):
        # DNS names are case-insensitive; a trailing dot is the same host.
        payload = Payload("https://evil.example.com/", "redirect", "")
        for location in ("https://EVIL.EXAMPLE.COM/",
                         "https://evil.example.com./",
                         "//EVIL.EXAMPLE.COM/x"):
            verdict, _ = classify(payload, 302, location, "")
            self.assertEqual(verdict, "OPEN-REDIRECT", location)

    def test_host_echo_is_case_insensitive(self):
        verdict, _ = classify(Payload("http://localhost/", "localhost", ""),
                              200, None, "RUN ON LOCALHOST FOR DEV")
        self.assertEqual(verdict, "FETCHED")

    def test_same_host_redirect_is_not_open(self):
        payload = Payload("https://evil.example.com/", "redirect", "")
        verdict, _ = classify(payload, 302,
                              "http://127.0.0.1:8901/other", "")
        self.assertEqual(verdict, "UNCLEAR")

    def test_dangerous_scheme_reflection(self):
        payload = Payload("javascript:alert(1)", "redirect", "")
        verdict, _ = classify(payload, 302, "javascript:alert(1)", "")
        self.assertEqual(verdict, "OPEN-REDIRECT")

    def test_metadata_marker(self):
        payload = Payload("http://169.254.169.254/latest/meta-data/",
                          "metadata", "")
        verdict, _ = classify(payload, 200, None,
                              "ami-id: ami-12345\ninstance-id: i-1")
        self.assertEqual(verdict, "FETCHED")

    def test_error_status(self):
        verdict, _ = classify(Payload("http://127.0.0.1/", "localhost", ""),
                              None, None, "")
        self.assertEqual(verdict, "ERROR")

    def test_term_safe_strips_escapes(self):
        self.assertEqual(term_safe("a\x1b[31mred\x1b[0m\nb"), "aredb")


class TestTargetSafety(unittest.TestCase):
    def test_placeholder_required(self):
        with self.assertRaises(ValueError):
            check_target_safety("http://127.0.0.1:8901/fetch", False)

    def test_loopback_allowed(self):
        check_target_safety("http://127.0.0.1:8901/fetch?url={payload}",
                            False)

    def test_public_needs_flag(self):
        with self.assertRaises(ValueError):
            check_target_safety("http://8.8.8.8/fetch?url={payload}", False)
        # With the flag, the safety check itself passes (no request is made).
        check_target_safety("http://8.8.8.8/fetch?url={payload}", True)

    def test_ipv6_loopback_allowed(self):
        # gethostbyname cannot resolve ::1, so IPv6 loopback targets
        # used to be rejected even though they are loopback.
        check_target_safety("http://[::1]:8901/fetch?url={payload}", False)

    def test_ipv6_public_needs_flag(self):
        with self.assertRaises(ValueError):
            check_target_safety(
                "http://[2606:4700:4700::1111]/fetch?url={payload}", False)
        check_target_safety(
            "http://[2606:4700:4700::1111]/fetch?url={payload}", True)


class TestCliValidation(unittest.TestCase):
    def test_empty_sets_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            _parse_sets("")
        self.assertEqual(ctx.exception.code, 2)

    def test_lab_port_out_of_range_rejected_cleanly(self):
        import argparse
        for port in (-1, 70000):
            self.assertEqual(
                cmd_lab(argparse.Namespace(port=port)), 2)


class TestLabIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.log, cls.port = start_lab(0)
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_canary_proves_server_side_fetch(self):
        canary = Payload(f"{self.base}/canary/proof", "localhost", "")
        finding = scan_one(f"{self.base}/fetch?url={{payload}}", canary)
        self.assertEqual(finding.verdict, "FETCHED")
        hits = [h for h in self.log.snapshot()
                if h["token"] == "proof"]
        self.assertEqual(len(hits), 1)

    def test_open_redirect_detected_without_following(self):
        payload = Payload("https://evil.example.com/", "redirect", "")
        finding = scan_one(f"{self.base}/redirect?next={{payload}}", payload)
        self.assertEqual(finding.verdict, "OPEN-REDIRECT")
        self.assertEqual(finding.target_status, 302)

    def test_full_scan_runs_all_groups(self):
        # Plus one canary payload: it guarantees a FETCHED verdict whatever
        # else listens on loopback in this environment.
        payloads = payloads_for() + [
            Payload(f"{self.base}/canary/fullscan", "localhost", "")
        ]
        findings = scan(
            f"{self.base}/fetch?url={{payload}}",
            payloads,
            timeout=5.0,
        )
        self.assertEqual(len(findings), len(payloads))
        verdicts = {f.verdict for f in findings}
        self.assertIn("FETCHED", verdicts)
        self.assertNotIn("ERROR", verdicts)

    def test_file_scheme_fetch_counts_as_fetched(self):
        # urllib file:// responses carry no HTTP status; the lab must still
        # report the read as a successful fetch, not a failure.
        finding = scan_one(f"{self.base}/fetch?url={{payload}}",
                           Payload("file:///etc/hostname", "scheme", ""))
        self.assertEqual(finding.verdict, "FETCHED")

    def test_missing_param_is_unclear_not_crash(self):
        # A fetcher that 400s without a block keyword is UNCLEAR, not ERROR.
        finding = scan_one(f"{self.base}/fetch?url={{payload}}",
                           Payload("", "localhost", ""))
        self.assertIn(finding.verdict, ("UNCLEAR", "BLOCKED", "ERROR"))


if __name__ == "__main__":
    unittest.main()
