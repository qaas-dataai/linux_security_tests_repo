import paramiko
from linux_security.ssh_config import EC2_HOST, EC2_USER, KEY_PATH

def run_remote(cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(EC2_HOST, username=EC2_USER, key_filename=KEY_PATH)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out, err = stdout.read().decode(), stderr.read().decode()
    ssh.close()
    return out.strip(), err.strip()
