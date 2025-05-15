from linux_security.utils_ssh import run_remote

def test_mysql():
    out, _ = run_remote("systemctl is-active mysql || systemctl is-active mariadb")
    print("MySQL/MariaDB status:", out)
    assert out == "active"
