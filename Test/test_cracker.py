from sidewinder.core.cracker import _parse_aircrack_line


def test_parse_aircrack_native_progress_line():
    progress = _parse_aircrack_line("[00:00:02] 23328/14344158 keys tested (10723.30 k/s)")

    assert progress is not None
    assert progress.keys_tested == 23328
    assert progress.total_keys == 14344158
    assert progress.keys_per_second == 10723300.0


def test_parse_aircrack_status_fields():
    eta = _parse_aircrack_line("Time left: 22 minutes, 15 seconds                          0.17%")
    current = _parse_aircrack_line("Current passphrase: 002584813")
    master = _parse_aircrack_line("Master Key     : E5 AB B7 E9 76 7E 0D B5")

    assert eta is not None
    assert eta.eta_text == "22 minutes, 15 seconds"
    assert eta.percent == 0.17
    assert current is not None
    assert current.current_key == "002584813"
    assert master is not None
    assert master.master_key == "E5 AB B7 E9 76 7E 0D B5"
