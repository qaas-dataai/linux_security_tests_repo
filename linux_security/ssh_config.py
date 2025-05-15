# EC2_HOST = "54.234.195.6"
# EC2_USER = "ubuntu"  # or ec2-user for Amazon Linux
# KEY_PATH = "/Users/ssingirikonda/workspace/linux_security_tests_repo/flask-app-key-ec2.pem"

import os

EC2_HOST = os.getenv("EC2_HOST", "54.234.195.6")
EC2_USER = os.getenv("EC2_USER", "ubuntu")

# Try Jenkins path, fallback to local path
jenkins_key_path = "/var/lib/jenkins/.ssh/flask-app-key-ec2.pem"
local_key_path = os.path.join(os.getcwd(), "flask-app-key-ec2.pem")

if os.path.exists(jenkins_key_path):
    KEY_PATH = jenkins_key_path
elif os.path.exists(local_key_path):
    KEY_PATH = local_key_path
else:
    raise FileNotFoundError("🔐 SSH key not found in Jenkins or local paths.")

