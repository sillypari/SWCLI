import asyncio
import unittest

from sidewinder.attacks.evil_twin import EvilTwinEngine


class EvilTwinTests(unittest.TestCase):
    def test_network_config_rejects_out_of_subnet_dhcp_range(self):
        engine = EvilTwinEngine(gateway_ip="10.0.0.1", dhcp_start="10.2.0.10")

        with self.assertRaisesRegex(ValueError, "same subnet"):
            engine._validate_network_config()

    def test_notice_mode_allows_common_connectivity_probe(self):
        engine = EvilTwinEngine()

        status, content_type, body = engine._portal_response(
            "notice",
            "Lab AP",
            "Authorized test",
            "/generate_204",
        )

        self.assertEqual(status, "204 No Content")
        self.assertEqual(content_type, "text/plain; charset=utf-8")
        self.assertEqual(body, "")

    def test_captive_mode_returns_portal_for_connectivity_probe(self):
        engine = EvilTwinEngine()

        status, content_type, body = engine._portal_response(
            "captive",
            "Lab AP",
            "Authorized test",
            "/generate_204",
        )

        self.assertEqual(status, "200 OK")
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertIn("Lab AP", body)
        self.assertIn("does not collect credentials", body)

    def test_tool_event_tracking_records_clients_and_leases(self):
        engine = EvilTwinEngine()
        logs = []

        async def run():
            async def safe_log(line):
                logs.append(line)

            await engine._record_tool_event(
                "airbase",
                "Client 00:11:22:33:44:55 associated",
                safe_log,
            )
            await engine._record_tool_event(
                "dnsmasq",
                "dnsmasq-dhcp: DHCPACK(at0) 10.0.0.42 00:11:22:33:44:55 phone",
                safe_log,
            )

        asyncio.run(run())

        self.assertIn("00:11:22:33:44:55".upper(), engine.stats.associated_clients)
        self.assertEqual(engine.stats.dhcp_leases["00:11:22:33:44:55".upper()], "10.0.0.42")
        self.assertTrue(any("Client associated" in line for line in logs))
        self.assertTrue(any("DHCP lease" in line for line in logs))


if __name__ == "__main__":
    unittest.main()
