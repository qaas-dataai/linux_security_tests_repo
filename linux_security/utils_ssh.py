import os
import subprocess
import paramiko
from linux_security.ssh_config import EC2_HOST, EC2_USER, KEY_PATH

def run_remote(cmd):
    # 🧠 Option 1: Use CI_MODE env flag
    ci_mode = os.getenv("CI_MODE", "").lower() == "true"

    # 🧠 Option 2: Detect if running as Jenkins user
    is_jenkins = os.getenv("USER") == "jenkins"

    if ci_mode or is_jenkins:
        print(f"🔁 Running locally: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return result.stdout.strip(), ""
        except subprocess.CalledProcessError as e:
            return "", e.stderr.strip()
    else:
        print(f"🔁 Running via SSH: {cmd}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(EC2_HOST, username=EC2_USER, key_filename=KEY_PATH)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out, err = stdout.read().decode(), stderr.read().decode()
        ssh.close()
        return out.strip(), err.strip()
