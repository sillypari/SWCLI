from sidewinder.core import monitor
from sidewinder.core.adapter import AdapterInfo, _collapse_monitor_vifs


def test_collapse_monitor_vif_hides_base_adapter():
    base = AdapterInfo(
        iface="wlo1",
        phy="phy0",
        chipset="MT7902",
        mac="AA:BB:CC:DD:EE:FF",
        current_mode="managed",
    )
    mon = AdapterInfo(
        iface="wlo1mon",
        phy="phy0",
        chipset="MT7902",
        mac="AA:BB:CC:DD:EE:FF",
        current_mode="monitor",
    )

    collapsed = _collapse_monitor_vifs([base, mon])

    assert [adapter.iface for adapter in collapsed] == ["wlo1mon"]


def test_infer_base_iface_from_standard_monitor_vif(monkeypatch):
    class FakePath:
        def __init__(self, path: str) -> None:
            self.path = path

        def exists(self) -> bool:
            return self.path == "/sys/class/net/wlo1"

    monkeypatch.setattr(monitor, "Path", FakePath)

    assert monitor.infer_base_iface("wlo1mon") == "wlo1"
    assert monitor.infer_base_iface("mon0") == ""
