"""Tests for the CaptivePortalEngine (airgeddon-style captive portal)."""
import asyncio
import os
import tempfile
import unittest
import unittest.mock

from sidewinder.attacks.captive_portal import (
    CaptivePortalConfig,
    CaptivePortalEngine,
    CaptivePortalStats,
    PortalMode,
    DetectedOS,
    ALL_PROBE_PATHS,
    WHITELISTED_DOMAINS,
    lookup_manufacturer,
)


class CaptivePortalConfigTests(unittest.TestCase):
    """Tests for CaptivePortalConfig validation."""

    def test_valid_config(self):
        config = CaptivePortalConfig()
        self.assertEqual(config.gateway_ip, "10.0.0.1")
        self.assertEqual(config.portal_port, 80)
        self.assertEqual(config.portal_mode, PortalMode.NOTICE)

    def test_invalid_dhcp_range(self):
        with self.assertRaisesRegex(ValueError, "DHCP start must be"):
            CaptivePortalConfig(dhcp_start="10.0.0.200", dhcp_end="10.0.0.10")

    def test_out_of_subnet_gateway(self):
        with self.assertRaisesRegex(ValueError, "same subnet"):
            CaptivePortalConfig(gateway_ip="10.0.0.1", dhcp_start="192.168.1.10")

    def test_invalid_port(self):
        with self.assertRaisesRegex(ValueError, "port must be"):
            CaptivePortalConfig(portal_port=99999)

    def test_netmask_property(self):
        config = CaptivePortalConfig(cidr_prefix=24)
        self.assertEqual(config.netmask, "255.255.255.0")

    def test_whitelist_domains_default(self):
        config = CaptivePortalConfig()
        self.assertIn("google.com", config.whitelist_domains)
        self.assertIn("gstatic.com", config.whitelist_domains)


class CaptivePortalStatsTests(unittest.TestCase):
    """Tests for CaptivePortalStats tracking."""

    def test_record_request(self):
        stats = CaptivePortalStats()
        stats.record_request("192.168.1.100", "/generate_204", "Android", DetectedOS.ANDROID)

        self.assertEqual(stats.portal_hits, 1)
        self.assertEqual(len(stats.portal_requests), 1)
        self.assertEqual(stats.detected_os["192.168.1.100"], DetectedOS.ANDROID)

    def test_record_multiple_requests(self):
        stats = CaptivePortalStats()
        stats.record_request("192.168.1.100", "/path1", "UA1", DetectedOS.ANDROID)
        stats.record_request("192.168.1.101", "/path2", "UA2", DetectedOS.IOS)

        self.assertEqual(stats.portal_hits, 2)
        self.assertEqual(len(stats.detected_os), 2)

    def test_get_client_os(self):
        stats = CaptivePortalStats()
        stats.record_request("192.168.1.100", "/", "", DetectedOS.WINDOWS)

        self.assertEqual(stats.get_client_os("192.168.1.100"), DetectedOS.WINDOWS)
        self.assertEqual(stats.get_client_os("192.168.1.200"), DetectedOS.UNKNOWN)

    def test_request_limit(self):
        stats = CaptivePortalStats()
        for i in range(150):
            stats.record_request(f"192.168.1.{i % 256}", f"/path{i}", "", DetectedOS.UNKNOWN)

        self.assertEqual(len(stats.portal_requests), 100)


class ProbePathsTests(unittest.TestCase):
    """Tests for OS-specific probe paths."""

    def test_all_probe_paths_populated(self):
        self.assertGreater(len(ALL_PROBE_PATHS), 0)

    def test_android_probe_paths(self):
        self.assertIn("/generate_204", ALL_PROBE_PATHS)
        self.assertIn("/gen_204", ALL_PROBE_PATHS)

    def test_ios_probe_paths(self):
        self.assertIn("/hotspot-detect.html", ALL_PROBE_PATHS)
        self.assertIn("/library/test/success.html", ALL_PROBE_PATHS)

    def test_windows_probe_paths(self):
        self.assertIn("/ncsi.txt", ALL_PROBE_PATHS)
        self.assertIn("/connecttest.txt", ALL_PROBE_PATHS)

    def test_linux_probe_paths(self):
        self.assertIn("/canonical.html", ALL_PROBE_PATHS)

    def test_whitelist_domains(self):
        self.assertIn("google.com", WHITELISTED_DOMAINS)
        self.assertIn("gstatic.com", WHITELISTED_DOMAINS)

    def test_notice_mode_serves_probe_success(self):
        engine = CaptivePortalEngine(CaptivePortalConfig(portal_mode=PortalMode.NOTICE))

        self.assertTrue(engine._should_serve_probe_success("/generate_204"))

    def test_captive_mode_does_not_serve_probe_success(self):
        engine = CaptivePortalEngine(CaptivePortalConfig(portal_mode=PortalMode.CAPTIVE))

        self.assertFalse(engine._should_serve_probe_success("/generate_204"))

    def test_password_mode_does_not_serve_probe_success(self):
        engine = CaptivePortalEngine(CaptivePortalConfig(portal_mode=PortalMode.PASSWORD))

        self.assertFalse(engine._should_serve_probe_success("/hotspot-detect.html"))


class DetectOSTests(unittest.TestCase):
    """Tests for OS detection from User-Agent strings."""

    def setUp(self):
        self.engine = CaptivePortalEngine()

    def test_detect_android(self):
        ua = "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36"
        self.assertEqual(self.engine._detect_os(ua), DetectedOS.ANDROID)

    def test_detect_ios(self):
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
        self.assertEqual(self.engine._detect_os(ua), DetectedOS.IOS)

    def test_detect_ipad(self):
        ua = "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)"
        self.assertEqual(self.engine._detect_os(ua), DetectedOS.IOS)

    def test_detect_windows(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        self.assertEqual(self.engine._detect_os(ua), DetectedOS.WINDOWS)

    def test_detect_macos(self):
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        self.assertEqual(self.engine._detect_os(ua), DetectedOS.MACOS)

    def test_detect_linux(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64)"
        self.assertEqual(self.engine._detect_os(ua), DetectedOS.LINUX)

    def test_detect_unknown(self):
        ua = "SomeCustomBot/1.0"
        self.assertEqual(self.engine._detect_os(ua), DetectedOS.UNKNOWN)


class PortalHTMLGenerationTests(unittest.TestCase):
    """Tests for captive portal HTML generation."""

    def setUp(self):
        self.config = CaptivePortalConfig(
            portal_title="Test Network",
            portal_message="Test message",
            essid="TEST-AP",
        )
        self.engine = CaptivePortalEngine(config=self.config)

    def test_generate_portal_html(self):
        html = self.engine._generate_portal_html("/test", "192.168.1.100", DetectedOS.ANDROID)

        self.assertIn("Test Network", html)
        self.assertIn("Test message", html)
        self.assertIn("TEST-AP", html)

    def test_generate_portal_html_escapes(self):
        html = self.engine._generate_portal_html("/", "10.0.0.1", DetectedOS.UNKNOWN)
        # Should not contain unescaped HTML
        self.assertNotIn("<script>", html)

    def test_captive_mode_content(self):
        self.config.portal_mode = PortalMode.CAPTIVE
        html = self.engine._generate_portal_html("/", "10.0.0.1", DetectedOS.UNKNOWN)
        self.assertIn("requires authorization", html)

    def test_notice_mode_content(self):
        self.config.portal_mode = PortalMode.NOTICE
        html = self.engine._generate_portal_html("/", "10.0.0.1", DetectedOS.UNKNOWN)
        self.assertIn("Network Notice", html)


class PasswordAttemptTests(unittest.TestCase):
    """Tests for password attempt recording."""

    def test_record_valid_attempt(self):
        stats = CaptivePortalStats()
        stats.record_password_attempt("192.168.1.100", "password123", True)

        self.assertEqual(len(stats.password_attempts), 1)
        self.assertTrue(stats.password_found)
        self.assertEqual(stats.captured_password, "password123")

    def test_record_invalid_attempt(self):
        stats = CaptivePortalStats()
        stats.record_password_attempt("192.168.1.100", "wrongpass", False)

        self.assertEqual(len(stats.password_attempts), 1)
        self.assertFalse(stats.password_found)
        self.assertEqual(stats.captured_password, "")

    def test_multiple_attempts(self):
        stats = CaptivePortalStats()
        stats.record_password_attempt("192.168.1.100", "wrong1", False)
        stats.record_password_attempt("192.168.1.101", "correct1", True)
        stats.record_password_attempt("192.168.1.102", "wrong2", False)

        self.assertEqual(len(stats.password_attempts), 3)
        self.assertTrue(stats.password_found)
        self.assertEqual(stats.captured_password, "correct1")

    def test_attempt_timestamp(self):
        stats = CaptivePortalStats()
        stats.record_password_attempt("192.168.1.100", "pass1", False)

        attempt = stats.password_attempts[0]
        self.assertIn("timestamp", attempt)
        self.assertEqual(attempt["client_ip"], "192.168.1.100")
        self.assertEqual(attempt["password"], "pass1")
        self.assertFalse(attempt["valid"])

    def test_unverified_attempt_does_not_mark_password_found(self):
        stats = CaptivePortalStats()
        stats.record_password_attempt("192.168.1.100", "pass1", None)

        self.assertFalse(stats.password_found)
        self.assertEqual(stats.captured_password, "")
        self.assertIsNone(stats.password_attempts[0]["valid"])


class PasswordHTMLTests(unittest.TestCase):
    """Tests for password mode HTML generation."""

    def setUp(self):
        self.config = CaptivePortalConfig(
            portal_title="Test Network",
            portal_message="Test message",
            essid="TEST-AP",
            portal_mode=PortalMode.PASSWORD,
        )
        self.engine = CaptivePortalEngine(config=self.config)

    def test_password_mode_login_form(self):
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.ANDROID)
        self.assertIn('type="password"', html)
        self.assertIn('name="password"', html)
        self.assertIn('method="post"', html)
        self.assertIn("Wireless Password", html)

    def test_password_mode_submit_button(self):
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)
        self.assertIn("Connect", html)
        self.assertIn('type="submit"', html)

    def test_router_update_variant_changes_copy(self):
        self.config.portal_variant = "tplink"
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("Firmware Update Failed", html)
        self.assertIn("Restore Network Connection", html)

    def test_signin_variant_changes_copy(self):
        self.config.portal_variant = "airtel"
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("Airtel WiFi", html)
        self.assertIn("Sign In", html)

    def test_jio_variant_changes_copy(self):
        self.config.portal_variant = "jio"
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("Jio", html)
        self.assertIn("Connect", html)

    def test_hotel_variant_changes_copy(self):
        self.config.portal_variant = "hotel"
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("Guest WiFi", html)
        self.assertIn("Connect to WiFi", html)

    def test_generic_router_with_known_manufacturer(self):
        self.config.portal_variant = "generic_router"
        self.config.router_manufacturer = "Netgear"
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("Netgear", html)
        self.assertIn("Firmware Update Failed", html)
        self.assertIn("Restore Network Connection", html)

    def test_generic_router_with_no_manufacturer(self):
        self.config.portal_variant = "generic_router"
        self.config.router_manufacturer = ""
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("Router", html)
        self.assertIn("Firmware Update Failed", html)

    def test_generic_router_manufacturer_in_title(self):
        self.config.portal_variant = "generic_router"
        self.config.router_manufacturer = "ASUS"
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("<title>ASUS - Firmware Update</title>", html)

    def test_tplink_variant_has_brand_footer(self):
        self.config.portal_variant = "tplink"
        html = self.engine._generate_login_html("10.0.0.1", DetectedOS.UNKNOWN)

        self.assertIn("TP-Link", html)
        self.assertIn("Archer AX50", html)

    def test_received_html_for_unverified_attempt(self):
        html = self.engine._generate_received_html("192.168.1.50", DetectedOS.ANDROID)

        self.assertIn("Credentials Received", html)

    def test_success_html(self):
        html = self.engine._generate_success_html("192.168.1.50", DetectedOS.IOS, "mypass123")
        self.assertIn("Credentials Verified", html)
        self.assertIn("Firmware Updated Successfully", html)

    def test_failure_html(self):
        html = self.engine._generate_failure_html("192.168.1.50", DetectedOS.WINDOWS)
        self.assertIn("Incorrect Password", html)
        self.assertIn("incorrect", html.lower())

    def test_success_html_escapes_special_chars(self):
        self.config.essid = '<script>alert(1)</script>'
        self.config.portal_title = 'Test "Network"'
        html = self.engine._generate_success_html("10.0.0.1", DetectedOS.UNKNOWN, "pass")
        self.assertNotIn("<script>alert", html)

    def test_failure_html_escapes_special_chars(self):
        html = self.engine._generate_failure_html("10.0.0.1", DetectedOS.UNKNOWN)
        self.assertIn("Incorrect Password", html)


class SaveAttemptTests(unittest.TestCase):
    """Tests for password attempt file saving."""

    def setUp(self):
        self.config = CaptivePortalConfig(
            portal_title="Test Net",
            essid="TESTNET",
            bssid="AA:BB:CC:DD:EE:FF",
        )
        self.engine = CaptivePortalEngine(config=self.config)
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_save_attempt_creates_file(self):
        with unittest.mock.patch("sidewinder.core.paths.passwords_dir", return_value=self.test_dir):
            filepath = self.engine._save_attempt("192.168.1.100", "testpass", False)
            self.assertTrue(os.path.exists(filepath))
            with open(filepath) as f:
                content = f.read()
            self.assertIn("testpass", content)
            self.assertIn("INVALID", content)
            self.assertIn("AA:BB:CC:DD:EE:FF", content)

    def test_save_valid_attempt(self):
        with unittest.mock.patch("sidewinder.core.paths.passwords_dir", return_value=self.test_dir):
            filepath = self.engine._save_attempt("192.168.1.100", "correctpass", True)
            with open(filepath) as f:
                content = f.read()
            self.assertIn("VALID", content)
            self.assertIn("correctpass", content)

    def test_save_attempt_updates_master_log(self):
        with unittest.mock.patch("sidewinder.core.paths.passwords_dir", return_value=self.test_dir):
            self.engine._save_attempt("192.168.1.100", "pass1", False)
            self.engine._save_attempt("192.168.1.101", "pass2", True)

            master_path = os.path.join(self.test_dir, "passwords.txt")
            self.assertTrue(os.path.exists(master_path))
            with open(master_path) as f:
                content = f.read()
            self.assertIn("pass1", content)
            self.assertIn("pass2", content)
            self.assertIn("TESTNET", content)

    def test_save_unverified_attempt(self):
        with unittest.mock.patch("sidewinder.core.paths.passwords_dir", return_value=self.test_dir):
            filepath = self.engine._save_attempt("192.168.1.100", "maybepass", None)
            with open(filepath) as f:
                content = f.read()
            self.assertIn("UNVERIFIED", content)
            self.assertIn("maybepass", content)


class OUILookupTests(unittest.TestCase):
    """Tests for BSSID OUI manufacturer lookup."""

    def test_known_manufacturer(self):
        result = lookup_manufacturer("00:14:6C:AA:BB:CC")
        self.assertEqual(result, "Netgear")

    def test_known_manufacturer_tp_link(self):
        result = lookup_manufacturer("30:B5:C2:12:34:56")
        self.assertEqual(result, "TP-Link")

    def test_known_manufacturer_asus(self):
        result = lookup_manufacturer("34:97:F6:AB:CD:EF")
        self.assertEqual(result, "ASUS")

    def test_known_manufacturer_case_insensitive(self):
        result = lookup_manufacturer("00:14:6c:AA:BB:CC")
        self.assertEqual(result, "Netgear")

    def test_unknown_manufacturer(self):
        result = lookup_manufacturer("FF:FF:FF:00:11:22")
        self.assertEqual(result, "")

    def test_none_bssid(self):
        result = lookup_manufacturer(None)
        self.assertEqual(result, "")

    def test_empty_bssid(self):
        result = lookup_manufacturer("")
        self.assertEqual(result, "")

    def test_short_bssid(self):
        result = lookup_manufacturer("00:14:6C")
        self.assertEqual(result, "Netgear")


class StatsSummaryTests(unittest.TestCase):
    """Tests for stats summary generation."""

    def test_get_stats_summary(self):
        config = CaptivePortalConfig()
        engine = CaptivePortalEngine(config=config)

        # Record some requests
        engine.stats.record_request("192.168.1.100", "/", "UA", DetectedOS.ANDROID)
        engine.stats.record_request("192.168.1.101", "/", "UA", DetectedOS.IOS)

        summary = engine.get_stats_summary()

        self.assertEqual(summary["portal_hits"], 2)
        self.assertEqual(summary["unique_clients"], 2)
        self.assertIn("android", summary["os_distribution"])
        self.assertIn("ios", summary["os_distribution"])


if __name__ == "__main__":
    unittest.main()
