from linux_security.utils_ssh import run_remote

def test_vsftpd():
    out, _ = run_remote("systemctl is-active vsftpd")
    print("vsftpd status:", out)
    assert out == "active"
