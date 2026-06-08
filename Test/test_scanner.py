import json

from sidewinder.core.scanner import ScanEngine


def test_scan_engine_initializes_network_store_and_parses_json_update():
    engine = ScanEngine()

    engine._parse_json(
        json.dumps(
            {
                "type": "update",
                "current_channel": 6,
                "networks": [
                    {
                        "bssid": "00:11:22:33:44:55",
                        "channel": 6,
                        "signal": -42,
                        "privacy": "WPA2",
                        "cipher": "CCMP",
                        "auth": "PSK",
                        "essid": "LabNet",
                    }
                ],
                "clients": [],
            }
        ),
        on_network=None,
        on_client=None,
    )

    networks = engine.get_networks()

    assert len(networks) == 1
    assert networks[0].bssid == "00:11:22:33:44:55"
    assert networks[0].essid == "LabNet"
    assert engine.get_stats()["networks"] == 1


def test_scan_engine_preserves_eapol_after_later_update_clears_flag():
    engine = ScanEngine()
    first = {
        "type": "update",
        "networks": [
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 11,
                "signal": -50,
                "privacy": "WPA2",
                "cipher": "CCMP",
                "auth": "PSK",
                "essid": "Target",
                "eapol": True,
            }
        ],
        "clients": [],
    }
    second = {
        "type": "update",
        "networks": [
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 11,
                "signal": -51,
                "privacy": "WPA2",
                "cipher": "CCMP",
                "auth": "PSK",
                "essid": "Target",
                "eapol": False,
            }
        ],
        "clients": [],
    }

    engine._parse_json(json.dumps(first), on_network=None, on_client=None)
    engine._parse_json(json.dumps(second), on_network=None, on_client=None)

    networks = engine.get_networks()
    assert networks[0].eapol is True
    assert "AA:BB:CC:DD:EE:FF" in engine.eapol_bssids


def test_scan_engine_promotes_client_eapol_to_network():
    engine = ScanEngine()
    update = {
        "type": "update",
        "networks": [
            {
                "bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 11,
                "signal": -50,
                "privacy": "WPA2",
                "cipher": "CCMP",
                "auth": "PSK",
                "essid": "Target",
            }
        ],
        "clients": [
            {
                "mac": "00:11:22:33:44:55",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "signal": -60,
                "packets": 4,
                "eapol": True,
            }
        ],
    }

    engine._parse_json(json.dumps(update), on_network=None, on_client=None)

    assert engine.get_networks()[0].eapol is True
