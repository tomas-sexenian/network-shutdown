# 🚨 Network Shutdown

A Python tool to disrupt a local network by sending ARP spoofing packets using Scapy.

---

## 🛠 Requirements

- Python 3.11 or 3.12 (recommended)
- [Poetry](https://python-poetry.org/docs/#installation) installed
- Admin/root privileges to run the script

---

## 📦 Installation

### 1. Clone or download the project

    git clone https://github.com/your-username/network-shutdown.git
    cd network-shutdown

### 2. Configure Python version (if needed)
Ensure Python 3.11+ is installed:

    python3 --version

If necessary, install a compatible version using a version manager like pyenv.

### 3. Set up the virtual environment

    poetry env use 3.11  # or replace with your installed version like 3.12
    poetry install

### 4. Activate the environment

    poetry shell

## 🚀 Running the Script
Because the script interacts with your network, you must run it with root privileges:
sudo poetry run python network_shutdown.py


## 🧪 Development Notes
Script uses scapy for packet crafting and sending.
