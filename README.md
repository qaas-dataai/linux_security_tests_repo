**Linux Security & Compliance Functional Test Suite**

This repository provides a full-blown, automated security and system compliance test suite for validating critical configurations across Linux servers and installed applications.

It uses Python + Paramiko + Pytest to connect to remote Linux systems over SSH and run categorized test cases that check:

🔒 Security settings
🧾 Log integrity
🧪 Service health
📊 System metrics
🚨 Vulnerabilities
✅ Compliance enforcement

---

## 📁 Repo Structure

```
linux_security_tests_repo/
├── linux_security/
│   ├── utils_ssh.py              # SSH command execution logic using paramiko
│   ├── ssh_config.py             # SSH host, user, key path settings
├── tests/
│   ├── test_apache_suite.py     # Apache2-specific validations
│   ├── test_ssh_suite.py        # SSH daemon & config checks
│   ├── test_vsftpd_suite.py     # FTP service compliance tests
│   ├── test_mysql_pg_suite.py   # DB service validation
│   ├── test_django_flask_suite.py # App runtime environment tests
├── configs/                     # Device/env-specific configs for K8s or manual use
│   ├── device_model_a.yaml
│   └── device_model_b.yaml
├── k8s/                         # Kubernetes configs for CI/CD
│   ├── configmap.yaml
│   └── job_template.yaml
├── Dockerfile                   # Containerized test execution setup
├── requirements.txt
├── README.md
```

---

## ⚙️ Setup Instructions

### 🔧 Local (Virtualenv) Setup

1. Clone the repo

```bash
git clone https://github.com/qaas-dataai/linux_security_tests_repo.git
cd linux_security_tests_repo
```

2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

4. Configure SSH settings
   Edit `linux_security/ssh_config.py`:

```python
EC2_HOST = "your-remote-ip"
EC2_USER = "ubuntu"
KEY_PATH = "/full/path/to/your/flask-app-key-ec2.pem"
```

5. Run the test suite

```bash
pytest tests/ --html=report.html --self-contained-html
```

---

### 🐳 Docker Setup

1. Build Docker image

```bash
docker build -t linux-security-tests .
```

2. Run the container with tests

```bash
docker run --rm linux-security-tests
```

You can also mount SSH keys and configs if needed using `-v` flags.

---

### ☸️ Kubernetes Execution

1. Apply ConfigMap with device configs

```bash
kubectl apply -f k8s/configmap.yaml
```

2. Deploy test job per device or use `job_template.yaml`

```bash
kubectl apply -f k8s/job_template.yaml
```

The container will pull the correct YAML config per device and execute security tests accordingly.

---

## 🧪 Test Categories Covered

* `@security` – key config checks like SSH hardening, login limits
* `@logs` – log file location, rotation, and access
* `@status` – service up/down state
* `@performance` – CPU, memory, disk use
* `@vulnerability` – weak permissions, world-writable files
* `@compliance` – cert validity, passwd/shadow config
* `@recovery` – systemd fallback, daemon restarts

---

## 📦 Dependencies

Listed in `requirements.txt`:

```
pytest
paramiko
pytest-html
```

---

## 📝 Notes

* Make sure your private key file (`.pem`) is `chmod 400` and owned by your user
* Tests assume passwordless SSH access via key
* You can tag and filter tests using `-m marker_name`

---

## ❓ Questions?

Open an issue or contact [@qaas-dataai](https://github.com/qaas-dataai) on GitHub.
