import os
import subprocess
import paramiko
import tempfile

from linux_security.ssh_config import EC2_HOST, EC2_USER

def get_key_path():
    pem_env = os.environ.get("EC2_KEY")

    if pem_env:
        print("🔐 Using EC2_KEY from Jenkins secret text")
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
        temp_file.write(pem_env)
        temp_file.close()
        os.chmod(temp_file.name, 0o600)
        return temp_file.name
    else:
        # Correctly resolve path to repo root from subdir
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        default_key_path = os.path.join(repo_root, "flask-app-key-ec2.pem")
        print(f"💻 Using local .pem file from repo root: {default_key_path}")
        return default_key_path


def run_remote(cmd):
    """
    Run a command:
    - Locally if CI_MODE=true or running as Jenkins
    - Remotely via SSH otherwise
    """
    ci_mode = os.getenv("CI_MODE", "").lower() == "true"
    is_jenkins = os.getenv("USER") == "jenkins"

    if ci_mode or is_jenkins:
        print(f"⚙️  Running locally: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            return result.stdout.strip(), ""
        except subprocess.CalledProcessError as e:
            return "", e.stderr.strip()
    else:
        print(f"🌐 Running via SSH on EC2: {cmd}")
        key_path = get_key_path()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(EC2_HOST, username=EC2_USER, key_filename=key_path)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out, err = stdout.read().decode(), stderr.read().decode()
        ssh.close()
        return out.strip(), err.strip()
