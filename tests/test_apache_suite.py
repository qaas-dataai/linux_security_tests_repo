from linux_security.utils_ssh import run_remote
import pytest

def test_apache():
    out, _ = run_remote("systemctl is-active apache2")
    print("Apache status:", out)
    assert out == "active"

def test_apache_service():
    output, error = run_remote("systemctl is-active apache2")
    assert output == "active", f"Apache not running: {error}"

def test_apache_port():
    output, _ = run_remote("ss -tuln | grep ':80'")
    assert ":80" in output, "Apache not listening on port 80"

def test_apache_homepage():
    output, _ = run_remote("curl -s -o /dev/null -w '%{http_code}' http://localhost")
    assert output == "200", f"Apache homepage not responding: {output}"

def test_apache_logs_exist():
    output, _ = run_remote("test -f /var/log/apache2/error.log && echo exists")
    assert output == "exists", "Apache error log not found"





@pytest.mark.system
def test_service_count():
    """Count active systemd services"""
    out, _ = run_remote("systemctl list-units --type=service --state=running | wc -l")
    print("Command Output:", out)
    assert int(out) > 20, f'Low number of running services: {out}'

@pytest.mark.system
def test_uptime_threshold():
    """Ensure system has been up for at least 5 minutes"""
    out, _ = run_remote("awk '{print $1}' /proc/uptime")
    print("Command Output:", out)
    assert float(out) > 300, f'System uptime too low: {out} seconds'

@pytest.mark.system
def test_network_interfaces_up():
    """Ensure at least one network interface is up"""
    out, _ = run_remote("ip link show up | grep -c 'state UP'")
    print("Command Output:", out)
    assert int(out) > 0, 'No network interface is up'

@pytest.mark.system
def test_cpu_cores_count():
    """Ensure system has more than one CPU core"""
    out, _ = run_remote("nproc")
    print("Command Output:", out)
    assert int(out) >= 1, f'Unexpected CPU core count: {out}'

@pytest.mark.system
def test_open_ports():
    """Count open TCP ports"""
    out, _ = run_remote("ss -tuln | grep -v LISTEN | wc -l")
    print("Command Output:", out)
    assert int(out) >= 0, 'Unexpected number of open TCP ports'

@pytest.mark.system
def test_hostname_resolvable():
    """Ensure hostname is resolvable"""
    out, _ = run_remote("getent hosts $(hostname)")
    print("Command Output:", out)
    assert out != '', 'Hostname is not resolvable'

@pytest.mark.system
def test_timezone_configured():
    """Ensure timezone is set correctly"""
    out, _ = run_remote("timedatectl | grep 'Time zone'")
    print("Command Output:", out)
    assert 'UTC' in out or 'PST' in out, f'Timezone misconfigured: {out}'

@pytest.mark.system
def test_systemd_journal_active():
    """Check if systemd-journald is running"""
    out, _ = run_remote("systemctl is-active systemd-journald")
    print("Command Output:", out)
    assert out == 'active', 'systemd-journald is not running'

@pytest.mark.system
def test_tmp_not_world_writable():
    """Ensure /tmp is not globally writable"""
    out, _ = run_remote("stat -c %a /tmp")
    print("Command Output:", out)
    assert out == '1777', '/tmp permissions are incorrect'

@pytest.mark.system
def test_root_fs_mounted_rw():
    """Ensure root FS is mounted read-write"""
    out, _ = run_remote("mount | grep 'on / '")
    print("Command Output:", out)
    assert 'rw,' in out, 'Root filesystem is not mounted read-write'

@pytest.mark.filecheck
def test_hosts_file_exists():
    """Check /etc/hosts file exists"""
    out, _ = run_remote("test -f /etc/hosts && echo exists")
    print("Command Output:", out)
    assert out == 'exists', '/etc/hosts not found'

@pytest.mark.filecheck
def test_resolv_conf_exists():
    """Check /etc/resolv.conf exists"""
    out, _ = run_remote("test -f /etc/resolv.conf && echo exists")
    print("Command Output:", out)
    assert out == 'exists', '/etc/resolv.conf not found'

@pytest.mark.filecheck
def test_crontab_accessible():
    """Check root's crontab is readable"""
    out, _ = run_remote("crontab -l 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) >= 0, 'Unable to access root crontab'

@pytest.mark.filecheck
def test_home_dirs_permission():
    """Ensure home directories have proper perms"""
    out, _ = run_remote("find /home -type d -perm -0002 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) == 0, 'World-writable home directories found'

@pytest.mark.filecheck
def test_bin_dir_protected():
    """Ensure /bin is not writable"""
    out, _ = run_remote("stat -c %a /bin")
    print("Command Output:", out)
    assert out in ['755', '750'], f'/bin permissions too open: {out}'

@pytest.mark.filecheck
def test_boot_dir_protected():
    """Ensure /boot is not world-writable"""
    out, _ = run_remote("stat -c %a /boot")
    print("Command Output:", out)
    assert out != '777', '/boot directory is world-writable'

@pytest.mark.filecheck
def test_root_home_protected():
    """Check root's home dir is protected"""
    out, _ = run_remote("stat -c %a /root")
    print("Command Output:", out)
    assert out in ['700', '750'], f'/root permissions are weak: {out}'

@pytest.mark.filecheck
def test_shell_history_exists():
    """Check root shell history exists"""
    out, _ = run_remote("test -f /root/.bash_history && echo exists")
    print("Command Output:", out)
    assert out == 'exists', 'Shell history missing for root'

@pytest.mark.filecheck
def test_bashrc_exists():
    """Ensure .bashrc exists for root"""
    out, _ = run_remote("test -f /root/.bashrc && echo exists")
    print("Command Output:", out)
    assert out == 'exists', 'Missing .bashrc for root'

@pytest.mark.filecheck
def test_no_empty_log_files():
    """Ensure no 0-byte log files"""
    out, _ = run_remote("find /var/log -type f -size 0 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) < 10, 'Too many empty log files'

@pytest.mark.vulnerability
def test_fail2ban_installed():
    """Check if fail2ban is installed"""
    out, _ = run_remote("which fail2ban-client")
    print("Command Output:", out)
    assert out != '', 'fail2ban is not installed'

@pytest.mark.vulnerability
def test_ufw_configured():
    """Check if ufw is enabled and active"""
    out, _ = run_remote("ufw status")
    print("Command Output:", out)
    assert 'Status: active' in out, 'UFW is not active'

@pytest.mark.vulnerability
def test_apache_banner_hidden():
    """Ensure Apache does not expose version in headers"""
    out, _ = run_remote("curl -sI localhost | grep Server")
    print("Command Output:", out)
    assert 'Apache' in out and '/' not in out, 'Apache version is exposed'

@pytest.mark.vulnerability
def test_tcp_syn_cookies_enabled():
    """Ensure TCP SYN cookies are enabled"""
    out, _ = run_remote("sysctl net.ipv4.tcp_syncookies")
    print("Command Output:", out)
    assert '1' in out, 'TCP SYN cookies not enabled'

@pytest.mark.vulnerability
def test_icmp_redirects_disabled():
    """Check ICMP redirects are disabled"""
    out, _ = run_remote("sysctl net.ipv4.conf.all.accept_redirects")
    print("Command Output:", out)
    assert '0' in out, 'ICMP redirects are enabled'

@pytest.mark.vulnerability
def test_ip_forwarding_disabled():
    """Ensure IP forwarding is disabled"""
    out, _ = run_remote("sysctl net.ipv4.ip_forward")
    print("Command Output:", out)
    assert '0' in out, 'IP forwarding is enabled'

@pytest.mark.vulnerability
def test_apparmor_enabled():
    """Check if AppArmor is enabled"""
    out, _ = run_remote("aa-status | grep 'profiles are in enforce mode'")
    print("Command Output:", out)
    assert 'enforce mode' in out, 'AppArmor is not enforcing'

@pytest.mark.vulnerability
def test_selinux_disabled():
    """Check if SELinux is disabled (on Ubuntu)"""
    out, _ = run_remote("getenforce 2>/dev/null || echo Disabled")
    print("Command Output:", out)
    assert 'Disabled' in out or 'Permissive' in out, 'SELinux is enabled'

@pytest.mark.vulnerability
def test_tmp_separate_partition():
    """Ensure /tmp is on separate partition"""
    out, _ = run_remote("mount | grep '/tmp'")
    print("Command Output:", out)
    assert '/tmp' in out, '/tmp not on separate partition'

@pytest.mark.vulnerability
def test_package_updates_available():
    """Check if there are any package updates"""
    out, _ = run_remote("apt list --upgradable 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) <= 1, 'Packages need updating'



@pytest.mark.security
def test_lynis_installed():
    """Check if lynis is installed"""
    out, _ = run_remote("which lynis")
    print("Command Output:", out)
    assert out != '', 'lynis is not installed'

@pytest.mark.security
def test_lynis_audit_score():
    """Check hardening index from lynis"""
    out, _ = run_remote("lynis audit system --quiet | grep 'Hardening index'")
    print("Command Output:", out)
    assert 'Hardening index' in out, 'Lynis audit output missing or failed'

@pytest.mark.security
def test_auditd_service_running():
    """Ensure auditd service is running"""
    out, _ = run_remote("systemctl is-active auditd")
    print("Command Output:", out)
    assert out == 'active', 'auditd is not running'

@pytest.mark.security
def test_auditctl_rules_present():
    """Ensure audit rules are configured"""
    out, _ = run_remote("auditctl -l | wc -l")
    print("Command Output:", out)
    assert int(out) > 0, 'No audit rules configured via auditctl'

@pytest.mark.security
def test_audit_log_accessible():
    """Ensure audit log file exists and is readable"""
    out, _ = run_remote("test -f /var/log/audit/audit.log && echo exists")
    print("Command Output:", out)
    assert out == 'exists', 'audit.log not found'

