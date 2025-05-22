import os
import pytest

@pytest.mark.sil
def test_boot_time_under_5_seconds():
    output = os.popen("systemd-analyze time").read()
    assert "Startup finished in" in output
    boot_time_str = output.split("Startup finished in")[1].split("s")[0].strip()
    seconds = float(boot_time_str)
    assert seconds < 5
