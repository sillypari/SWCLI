from sidewinder.core.adapter import AdapterInfo, get_best_adapter


def _adapter(iface: str, chipset: str, monitor: bool, injection: bool) -> AdapterInfo:
    return AdapterInfo(
        iface=iface,
        chipset=chipset,
        monitor_capable=monitor,
        injection_capable=injection,
    )


def test_mt7902_is_emergency_fallback_for_capture():
    mt7902 = _adapter("wlo1", "MT7902", monitor=True, injection=False)

    assert get_best_adapter([mt7902], "capture") is mt7902


def test_mt7902_is_emergency_fallback_for_deauth_and_injection():
    mt7902 = _adapter("wlo1", "MT7902", monitor=True, injection=True)

    assert get_best_adapter([mt7902], "deauth") is mt7902
    assert get_best_adapter([mt7902], "inject") is mt7902


def test_injection_adapter_still_wins_over_mt7902_for_capture():
    mt7902 = _adapter("wlo1", "MT7902", monitor=True, injection=False)
    rt5370 = _adapter("wlx001ea6c65744", "RT5370", monitor=True, injection=True)

    assert get_best_adapter([rt5370, mt7902], "capture") is rt5370


def test_injection_adapter_still_wins_over_mt7902_for_deauth():
    mt7902 = _adapter("wlo1", "MT7902", monitor=True, injection=True)
    rt5370 = _adapter("wlx001ea6c65744", "RT5370", monitor=True, injection=True)

    assert get_best_adapter([rt5370, mt7902], "deauth") is rt5370
