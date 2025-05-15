from linux_security.utils_ssh import run_remote

def test_django():
    out, _ = run_remote("systemctl is-active gunicorn || systemctl is-active uwsgi")
    print("Web app status:", out)
    assert out == "active"
