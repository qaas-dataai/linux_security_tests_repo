from linux_security.utils_ssh import run_remote
import pytest

def test_ssh():
    out, _ = run_remote("systemctl is-active ssh")
    print("SSH status:", out)
    assert out == "active"


@pytest.mark.ssh
def test_ssh_service_running():
    """Ensure SSH service is active"""
    out, _ = run_remote("systemctl is-active ssh")
    print("Command Output:", out)
    assert out == 'active', 'SSH service is not running'

@pytest.mark.ssh
def test_ssh_port_open():
    """Ensure SSH port 22 is open"""
    out, _ = run_remote("ss -tuln | grep ':22 '")
    print("Command Output:", out)
    assert ':22' in out, 'SSH port 22 is not open'

@pytest.mark.ssh
def test_sshd_config_exists():
    """Check sshd_config file exists"""
    out, _ = run_remote("test -f /etc/ssh/sshd_config && echo exists")
    print("Command Output:", out)
    assert out == 'exists', 'sshd_config does not exist'

@pytest.mark.ssh
def test_ssh_protocol_version():
    """Ensure SSH uses Protocol 2"""
    out, _ = run_remote("grep '^Protocol' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'Protocol 2' in out, 'SSH is not using Protocol 2'

@pytest.mark.ssh
def test_ssh_root_login_disabled():
    """Ensure SSH root login is disabled"""
    out, _ = run_remote("grep '^PermitRootLogin' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'no' in out, 'Root login is enabled in SSH'

@pytest.mark.ssh
def test_password_auth_disabled():
    """Ensure password authentication is disabled"""
    out, _ = run_remote("grep '^PasswordAuthentication' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'no' in out, 'Password authentication is enabled'

@pytest.mark.ssh
def test_auth_log_exists():
    """Check if auth log file exists"""
    out, _ = run_remote("test -f /var/log/auth.log && echo exists")
    print("Command Output:", out)
    assert out == 'exists', 'auth.log not found'

@pytest.mark.ssh
def test_failed_login_attempts():
    """Check for failed login attempts"""
    out, _ = run_remote("grep 'Failed password' /var/log/auth.log | wc -l")
    print("Command Output:", out)
    assert int(out) >= 0, 'Could not parse failed login attempts'

@pytest.mark.ssh
def test_last_login_logged():
    """Check if last login is recorded"""
    out, _ = run_remote("last -n 1 | grep -v 'wtmp begins'")
    print("Command Output:", out)
    assert out != '', 'No last login entry found'

@pytest.mark.ssh
def test_ssh_banner_configured():
    """Ensure SSH banner is configured"""
    out, _ = run_remote("grep '^Banner' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'Banner' in out and out.strip().split()[-1] != 'none', 'No SSH login banner configured'


import pytest


@pytest.mark.security
def test_password_auth_disabled():
    """Ensure password authentication is disabled"""
    out, _ = run_remote("grep '^PasswordAuthentication' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'no' in out, 'Password authentication is enabled'


@pytest.mark.security
def test_root_login_disabled():
    """Ensure SSH root login is disabled"""
    out, _ = run_remote("grep '^PermitRootLogin' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'no' in out, 'Root login is enabled'


@pytest.mark.security
def test_ssh_protocol_version():
    """Ensure SSH uses Protocol 2"""
    out, _ = run_remote("grep '^Protocol' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'Protocol 2' in out, 'SSH is not using Protocol 2'


@pytest.mark.security
def test_selinux_status():
    """Check SELinux is disabled or permissive"""
    out, _ = run_remote("getenforce 2>/dev/null || echo Disabled")
    print("Command Output:", out)
    assert 'Disabled' in out or 'Permissive' in out


@pytest.mark.security
def test_firewall_active():
    """Check if UFW or iptables firewall is active"""
    out, _ = run_remote("ufw status 2>/dev/null || iptables -L")
    print("Command Output:", out)
    assert 'active' in out or 'Chain' in out


@pytest.mark.security
def test_shadow_file_protected():
    """Ensure /etc/shadow is not world-readable"""
    out, _ = run_remote("stat -c %a /etc/shadow")
    print("Command Output:", out)
    assert out != '777'


@pytest.mark.security
def test_fail2ban_running():
    """Ensure fail2ban is active"""
    out, _ = run_remote("systemctl is-active fail2ban")
    print("Command Output:", out)
    assert out == 'active'


@pytest.mark.security
def test_sysctl_hardening():
    """Check IP forwarding is disabled"""
    out, _ = run_remote("sysctl net.ipv4.ip_forward")
    print("Command Output:", out)
    assert '0' in out


@pytest.mark.security
def test_ssh_banner_set():
    """Ensure SSH login banner is configured"""
    out, _ = run_remote("grep '^Banner' /etc/ssh/sshd_config")
    print("Command Output:", out)
    assert 'Banner' in out and 'none' not in out.lower()


@pytest.mark.security
def test_no_world_writable_files():
    """Detect world-writable files"""
    out, _ = run_remote("find / -type f -perm -0002 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) < 10


@pytest.mark.logs
def test_syslog_running():
    """Ensure syslog/rsyslog is running"""
    out, _ = run_remote("systemctl is-active rsyslog")
    print("Command Output:", out)
    assert out == 'active'


@pytest.mark.logs
def test_auth_log_exists():
    """Check if auth log file exists"""
    out, _ = run_remote("test -f /var/log/auth.log && echo exists")
    print("Command Output:", out)
    assert out == 'exists'


@pytest.mark.logs
def test_logrotate_cron():
    """Check logrotate cron exists"""
    out, _ = run_remote("test -f /etc/cron.daily/logrotate && echo exists")
    print("Command Output:", out)
    assert out == 'exists'


@pytest.mark.logs
def test_logrotate_config_valid():
    """Validate logrotate config"""
    out, _ = run_remote("logrotate --debug /etc/logrotate.conf | grep rotating")
    print("Command Output:", out)
    assert 'rotating' in out


@pytest.mark.logs
def test_apache_log_exists():
    """Ensure Apache log exists"""
    out, _ = run_remote("test -f /var/log/apache2/error.log && echo exists")
    print("Command Output:", out)
    assert out == 'exists'


@pytest.mark.logs
def test_recent_log_updates():
    """Check logs updated in last 24h"""
    out, _ = run_remote("find /var/log -type f -mtime -1 | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.logs
def test_log_permissions():
    """Ensure /var/log is protected"""
    out, _ = run_remote("stat -c %a /var/log")
    print("Command Output:", out)
    assert out in ['750', '755']


@pytest.mark.logs
def test_empty_log_files():
    """Detect empty log files"""
    out, _ = run_remote("find /var/log -type f -size 0 | wc -l")
    print("Command Output:", out)
    assert int(out) < 5


@pytest.mark.logs
def test_log_archiving():
    """Check for compressed log archives"""
    out, _ = run_remote("find /var/log -name '*.gz' | wc -l")
    print("Command Output:", out)
    assert int(out) >= 1


@pytest.mark.logs
def test_syslog_config_exists():
    """Ensure syslog.conf or rsyslog.conf exists"""
    out, _ = run_remote("test -f /etc/rsyslog.conf && echo exists")
    print("Command Output:", out)
    assert out == 'exists'


@pytest.mark.depth
def test_shadow_entries_count():
    """Check number of shadow entries"""
    out, _ = run_remote("cat /etc/shadow | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.depth
def test_sudoers_file_exists():
    """Check sudoers file exists"""
    out, _ = run_remote("test -f /etc/sudoers && echo exists")
    print("Command Output:", out)
    assert out == 'exists'


@pytest.mark.depth
def test_sudoers_permissions():
    """Ensure sudoers is protected"""
    out, _ = run_remote("stat -c %a /etc/sudoers")
    print("Command Output:", out)
    assert out == '440'


@pytest.mark.depth
def test_hidden_files_in_root():
    """Check for hidden files in /root"""
    out, _ = run_remote("ls -A /root | grep '^\.' | wc -l")
    print("Command Output:", out)
    assert int(out) >= 1


@pytest.mark.depth
def test_running_cron_jobs():
    """List number of running cron jobs"""
    out, _ = run_remote("ls /etc/cron*/* | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.depth
def test_etc_hosts_file():
    """Check hosts file entries"""
    out, _ = run_remote("cat /etc/hosts | wc -l")
    print("Command Output:", out)
    assert int(out) > 1


@pytest.mark.depth
def test_home_dir_access():
    """Validate home dir permissions"""
    out, _ = run_remote("find /home -perm -2 -type d | wc -l")
    print("Command Output:", out)
    assert int(out) == 0


@pytest.mark.depth
def test_backup_files_present():
    """Check for .bak/.old in /etc"""
    out, _ = run_remote("find /etc -type f -name '*.bak' -o -name '*.old' | wc -l")
    print("Command Output:", out)
    assert int(out) < 5


@pytest.mark.depth
def test_user_bin_permissions():
    """Ensure /usr/bin not world-writable"""
    out, _ = run_remote("stat -c %a /usr/bin")
    print("Command Output:", out)
    assert out in ['755', '750']


@pytest.mark.depth
def test_temp_files_cleanup():
    """Check /tmp for stale files"""
    out, _ = run_remote("find /tmp -type f -mtime +7 | wc -l")
    print("Command Output:", out)
    assert int(out) < 10


import pytest


@pytest.mark.penetration
def test_telnet_installed():
    """Check if telnet is installed"""
    out, _ = run_remote("which telnet")
    print("Command Output:", out)
    assert out != '', 'Telnet is not installed'


@pytest.mark.penetration
def test_telnet_port_closed():
    """Ensure telnet port 23 is not open"""
    out, _ = run_remote("ss -tuln | grep ':23' | wc -l")
    print("Command Output:", out)
    assert int(out) == 0, 'Telnet port 23 is open'


@pytest.mark.penetration
def test_nmap_scan_for_port_22():
    """Scan for open SSH port 22"""
    out, _ = run_remote("nmap -p 22 localhost | grep 'open'")
    print("Command Output:", out)
    assert '22/tcp open' in out


@pytest.mark.penetration
def test_nmap_scan_common_ports():
    """Nmap scan common ports"""
    out, _ = run_remote("nmap -F localhost | grep open | wc -l")
    print("Command Output:", out)
    assert int(out) >= 1


@pytest.mark.penetration
def test_ping_enabled():
    """Check if ping works (ICMP allowed)"""
    out, _ = run_remote("ping -c 1 127.0.0.1 | grep '1 received'")
    print("Command Output:", out)
    assert '1 received' in out


@pytest.mark.penetration
def test_reverse_dns_lookup():
    """Check reverse DNS lookup works"""
    out, _ = run_remote("host 127.0.0.1")
    print("Command Output:", out)
    assert 'localhost' in out


@pytest.mark.penetration
def test_traceroute_installed():
    """Check if traceroute is installed"""
    out, _ = run_remote("which traceroute")
    print("Command Output:", out)
    assert out != '', 'traceroute not installed'


@pytest.mark.penetration
def test_tcpdump_installed():
    """Check if tcpdump is installed"""
    out, _ = run_remote("which tcpdump")
    print("Command Output:", out)
    assert out != '', 'tcpdump not installed'


@pytest.mark.penetration
def test_netcat_installed():
    """Check if netcat (nc) is installed"""
    out, _ = run_remote("which nc")
    print("Command Output:", out)
    assert out != '', 'netcat not installed'


@pytest.mark.penetration
def test_whois_lookup():
    """Check whois utility is available"""
    out, _ = run_remote("which whois")
    print("Command Output:", out)
    assert out != '', 'whois not installed'


@pytest.mark.system
def test_system_uptime():
    """Get system uptime"""
    out, _ = run_remote("uptime -p")
    print("Command Output:", out)
    assert 'up' in out


@pytest.mark.system
def test_disk_root_usage():
    """Check root disk usage"""
    out, _ = run_remote("df -h / | awk 'NR==2 {print $5}' | tr -d '%'")
    print("Command Output:", out)
    assert int(out) < 90


@pytest.mark.system
def test_swap_usage():
    """Check swap usage is low"""
    out, _ = run_remote("free | grep Swap | awk '{print $3}'")
    print("Command Output:", out)
    assert int(out) < 512000


@pytest.mark.system
def test_logged_in_users():
    """Check number of users logged in"""
    out, _ = run_remote("who | wc -l")
    print("Command Output:", out)
    assert int(out) >= 0


@pytest.mark.system
def test_cpu_model_info():
    """Fetch CPU model info"""
    out, _ = run_remote("grep 'model name' /proc/cpuinfo | head -1")
    print("Command Output:", out)
    assert 'Intel' in out or 'AMD' in out


@pytest.mark.system
def test_active_users():
    """List active users"""
    out, _ = run_remote("who")
    print("Command Output:", out)
    assert out != '', 'No active users'


@pytest.mark.system
def test_env_variables():
    """Check environment variables loaded"""
    out, _ = run_remote("env | wc -l")
    print("Command Output:", out)
    assert int(out) > 10


@pytest.mark.system
def test_current_user():
    """Validate current user identity"""
    out, _ = run_remote("whoami")
    print("Command Output:", out)
    assert out != '', 'No current user'


@pytest.mark.system
def test_kernel_version():
    """Get kernel version"""
    out, _ = run_remote("uname -r")
    print("Command Output:", out)
    assert out.count('.') >= 1


@pytest.mark.system
def test_os_release_file():
    """Check for /etc/os-release"""
    out, _ = run_remote("cat /etc/os-release | grep PRETTY_NAME")
    print("Command Output:", out)
    assert 'PRETTY_NAME' in out


@pytest.mark.status
def test_apache_service_status():
    """Check Apache service status"""
    out, _ = run_remote("systemctl is-active apache2")
    print("Command Output:", out)
    assert out in ['active', 'inactive']


@pytest.mark.status
def test_ssh_service_status():
    """Check SSH service status"""
    out, _ = run_remote("systemctl is-active ssh")
    print("Command Output:", out)
    assert out == 'active'


@pytest.mark.status
def test_docker_service_status():
    """Check Docker service status (if exists)"""
    out, _ = run_remote("systemctl is-active docker 2>/dev/null || echo not_installed")
    print("Command Output:", out)
    assert out in ['active', 'inactive', 'not_installed']


@pytest.mark.status
def test_network_interfaces():
    """Check network interfaces status"""
    out, _ = run_remote("ip link show | grep -c 'state UP'")
    print("Command Output:", out)
    assert int(out) >= 1


@pytest.mark.status
def test_firewalld_status():
    """Check firewalld status"""
    out, _ = run_remote("systemctl is-active firewalld 2>/dev/null || echo not_installed")
    print("Command Output:", out)
    assert out in ['active', 'inactive', 'not_installed']


@pytest.mark.status
def test_mount_status():
    """Check mounted file systems"""
    out, _ = run_remote("mount | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.status
def test_sysctl_settings():
    """Get current sysctl settings"""
    out, _ = run_remote("sysctl -a | wc -l")
    print("Command Output:", out)
    assert int(out) > 100


@pytest.mark.status
def test_journal_logs():
    """Check systemd journal logs"""
    out, _ = run_remote("journalctl --no-pager | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.status
def test_service_count():
    """Count systemd services running"""
    out, _ = run_remote("systemctl list-units --type=service --state=running | wc -l")
    print("Command Output:", out)
    assert int(out) > 10


@pytest.mark.status
def test_cron_daemon_status():
    """Check cron service status"""
    out, _ = run_remote("systemctl is-active cron")
    print("Command Output:", out)
    assert out == 'active'


@pytest.mark.performance
def test_cpu_load():
    """Check 1-minute load average"""
    out, _ = run_remote("uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1")
    print("Command Output:", out)
    assert float(out.strip()) < 2.0


@pytest.mark.performance
def test_memory_usage():
    """Check memory usage free"""
    out, _ = run_remote("free | awk '/Mem:/ {print $4}'")
    print("Command Output:", out)
    assert int(out) > 10000


@pytest.mark.performance
def test_disk_io_stats():
    """Check disk IO stats available"""
    out, _ = run_remote("iostat 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.performance
def test_number_of_processes():
    """Count running processes"""
    out, _ = run_remote("ps aux | wc -l")
    print("Command Output:", out)
    assert int(out) > 10


@pytest.mark.performance
def test_top_cpu_process():
    """Check for highest CPU-consuming process"""
    out, _ = run_remote("ps -eo pid,comm,%cpu --sort=-%cpu | head -2 | tail -1")
    print("Command Output:", out)
    assert out != ''


@pytest.mark.performance
def test_top_mem_process():
    """Check for highest memory-consuming process"""
    out, _ = run_remote("ps -eo pid,comm,%mem --sort=-%mem | head -2 | tail -1")
    print("Command Output:", out)
    assert out != ''


@pytest.mark.performance
def test_io_wait_low():
    """Ensure IO wait is low"""
    out, _ = run_remote("vmstat 1 2 | tail -1 | awk '{print $16}'")
    print("Command Output:", out)
    assert int(out) < 20


@pytest.mark.performance
def test_cpu_idle_high():
    """Ensure CPU idle time is high"""
    out, _ = run_remote("vmstat 1 2 | tail -1 | awk '{print $15}'")
    print("Command Output:", out)
    assert int(out) > 60


@pytest.mark.performance
def test_uptime_high():
    """System uptime in hours"""
    out, _ = run_remote("awk '{print int($1/3600)}' /proc/uptime")
    print("Command Output:", out)
    assert int(out) >= 1


@pytest.mark.performance
def test_filesystem_inodes_usage():
    """Check inode usage"""
    out, _ = run_remote("df -i | awk 'NR>1 {print $5}' | tr -d '%' | sort -n | tail -1")
    print("Command Output:", out)
    assert int(out) < 80


@pytest.mark.vulnerability
def test_chkrootkit_status():
    """Run chkrootkit for infections"""
    out, _ = run_remote("chkrootkit | grep INFECTED")
    print("Command Output:", out)
    assert 'INFECTED' not in out


@pytest.mark.vulnerability
def test_lynis_hardening_index():
    """Check Lynis hardening index"""
    out, _ = run_remote("lynis audit system --quiet | grep 'Hardening index'")
    print("Command Output:", out)
    assert 'Hardening index' in out


@pytest.mark.vulnerability
def test_auditd_rules_present():
    """Check auditd rules exist"""
    out, _ = run_remote("auditctl -l | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.vulnerability
def test_ssh_known_hosts_permissions():
    """Check .ssh/known_hosts permissions"""
    out, _ = run_remote("stat -c %a ~/.ssh/known_hosts")
    print("Command Output:", out)
    assert out != '777'


@pytest.mark.vulnerability
def test_world_writable_dirs():
    """List world-writable dirs"""
    out, _ = run_remote("find / -type d -perm -0002 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) < 15


@pytest.mark.vulnerability
def test_packages_up_to_date():
    """Check for upgradable packages"""
    out, _ = run_remote("apt list --upgradable 2>/dev/null | wc -l")
    print("Command Output:", out)
    assert int(out) <= 1


@pytest.mark.vulnerability
def test_duplicate_uids():
    """Check for duplicate user IDs"""
    out, _ = run_remote("cut -d: -f3 /etc/passwd | sort | uniq -d | wc -l")
    print("Command Output:", out)
    assert int(out) == 0


@pytest.mark.vulnerability
def test_password_expiry_policy():
    """Ensure password expiry is enforced"""
    out, _ = run_remote("grep PASS_MAX_DAYS /etc/login.defs")
    print("Command Output:", out)
    assert '99999' not in out


@pytest.mark.vulnerability
def test_kernel_modules_loaded():
    """Check loaded kernel modules"""
    out, _ = run_remote("lsmod | wc -l")
    print("Command Output:", out)
    assert int(out) > 0


@pytest.mark.vulnerability
def test_open_ports_less_than_10():
    """Ensure number of open ports is low"""
    out, _ = run_remote("ss -tuln | grep -v '127.0.0.1' | wc -l")
    print("Command Output:", out)
    assert int(out) < 10
