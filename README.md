# Wi-Fi Security & Threat Intelligence Suite

  █░█░█ █▀ █░█ █▀▀ █▀▀ █░█ █▀█ █▄░█
  ▀▄▀▄▀ ▄█ █▀█ █▄▄ ██▄ ▀▄▀ █▄█ █░▀█

An advanced toolkit for performing deep-packet inspection and analysis of 802.11 wireless traffic. This suite combines rule-based threat detection, behavioral analysis, and physical-layer fingerprinting to provide security professionals and network administrators with a powerful system for identifying and responding to Wi-Fi vulnerabilities and attacks.

---

## Table of Contents
1.  [Core Features](#core-features)
2.  [System Architecture & Workflow](#system-architecture--workflow)
3.  [Project Components](#project-components)
4.  [Setup and Installation](#setup-and-installation)
5.  [Usage Guide](#usage-guide)
    - [Phase 1: Scanning with `scan.py`](#phase-1-scanning-with-scanpy)
    - [Phase 2: Analyzing Evidence with `analyze_evidence.py`](#phase-2-analyzing-evidence-with-analyze_evidencepy)
    - [Phase 3: RF Fingerprinting with `rfingertip.py`](#phase-3-rf-fingerprinting-with-rfingertippy)
6.  [Understanding the Detections](#understanding-the-detections)
7.  [Troubleshooting](#troubleshooting)
8.  [Contributing](#contributing)
9.  [License](#license)

---

## Core Features

-   **Multi-Layered Threat Detection**: Analyzes traffic from Layer 2 (802.11 management frames) to Layer 3 (ARP, DNS, DHCP), providing a holistic view of network security.
-   **Configurable Detection Engine**: All detection rules are loaded from an external `wifi_pcap_regex.json` file, allowing for easy updates and customization without modifying the core code.
-   **Automated Evidence Triage**: When threats are detected, the system automatically saves the specific malicious packets into a new, smaller `.pcap` file and generates a detailed text report, isolating crucial evidence for forensic analysis.
-   **Targeted Attack Analysis**: A dedicated script (`analyze_evidence.py`) filters through collected evidence to specifically identify unknown or hostile devices that are targeting your designated personal networks, while intelligently ignoring traffic from known neighbors.
-   **AI-Powered Mitigation Strategy**: Integrates with OpenAI (GPT-4o) and Anthropic (Claude 3.5 Sonnet) to provide expert-level, actionable recommendations for mitigating the specific threats that were detected.
-   **Physical Layer RF Fingerprinting**: A GUI-based tool (`rfingertip.py`) moves beyond MAC addresses to analyze the physical characteristics of wireless signals (RSSI and packet timing). By clustering devices with nearly identical hardware fingerprints, it can help uncover sophisticated MAC address spoofing attempts.

---

## System Architecture & Workflow

The toolkit is designed to be used in a sequential workflow, moving from broad scanning to focused analysis.

**Typical Workflow:**

1.  **Capture Traffic**: Use an external tool like `tcpdump`, `Wireshark`, or `airodump-ng` to capture Wi-Fi traffic and save it as a `.pcap` file in `/var/tmp/`.
2.  **Initial Scan (`scan.py`)**: Run the main scanner on the captured `.pcap` files. The scanner identifies a wide range of threats based on the JSON rule set. If any threats are found, it generates evidence files (`warning_*.pcap` and `warning_*.txt`) in the `evidence/` directory.
3.  **Evidence Analysis (`analyze_evidence.py`)**: Run the evidence analyzer to investigate the generated evidence files. This tool focuses on your personal networks (`MY_NETWORKS`) and tells you which unknown devices are attacking them.
4.  **Generate Mitigation Plan**: Use the AI integration within `analyze_evidence.py` to get a custom report on how to defend against the specific attacks you found.
5.  **Advanced Spoofing Detection (`rfingertip.py`)**: For deeper investigation, use the RF fingerprinting tool on either the original captures or the focused evidence files to look for signs of MAC spoofing.

---

## Project Components

| File / Directory            | Description                                                                                                                                                                                                |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core Scripts** |                                                                                                                                                                                                            |
| `scan.py`                   | The primary threat scanner. Analyzes `.pcap` files based on rules in the JSON file. **This is your starting point.** |
| `analyze_evidence.py`         | The secondary analysis tool. Investigates evidence saved by `scan.py` to identify attackers targeting your personal networks and generate AI reports.                                                     |
| `rfingertip.py`               | A GUI application for advanced RF fingerprinting analysis to detect potential MAC spoofing.                                                                                                                |
| **Configuration** |                                                                                                                                                                                                            |
| `wifi_pcap_regex.json`      | **Required.** The heart of the detection engine. This file defines all threats the scanner looks for. You can enable/disable rules or add new ones here.                                                      |
| `.env`                        | **Required.** A local, untracked file for storing sensitive API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).                                                                                                   |
| `.gitignore`                | Standard Git ignore file. Prevents sensitive files (`.env`) and generated directories from being committed.                                                                                                |
| **Generated Output** |                                                                                                                                                                                                            |
| `evidence/`                   | Automatically created directory where `.pcap` and `.txt` evidence files are saved by `scan.py`. **This is the output of Phase 1.** |
| `ai_reports/`                 | Automatically created directory where AI-generated mitigation reports are saved by `analyze_evidence.py`.                                                                                                 |
| `rf_fingerprints_report.json` | The JSON output from the `rfingertip.py` analysis, detailing suspicious device clusters.                                                                                                                 |

---

## Setup and Installation

**1. Prerequisites**
- Python 3.8+
- `git`
- (For Linux Live Scan) `network-manager` package (`nmcli` command).

**2. Clone the Repository**
```bash
git clone [your-repository-url]
cd detectwifihack
3. Create and Activate a Virtual Environment

Bash
# Create the virtual environment
python3 -m venv venv

# Activate it (macOS/Linux)
source venv/bin/activate
4. Install Dependencies
Create a file named requirements.txt with the content below, then run the installer.

Plaintext
# requirements.txt
scapy
pyqt6
matplotlib
numpy
python-dotenv
openai
anthropic
pick
Install all dependencies:

Bash
pip install -r requirements.txt
5. Set Up API Keys
Create a file named .env in the root of the project directory. Add your API keys, ensuring they are enclosed in quotes:

Code snippet
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
6. Configure Your Networks
This is a critical step for accurate analysis. Open scan.py and modify the network dictionaries:

MY_NETWORKS: Add your personal, trusted Access Points here. The analyzer will focus on attacks directed at these devices.
KNOWN_NETWORKS: Add your trusted neighbors' APs here. The analyzer will ignore traffic originating from these devices, preventing false positives.
Python
# In scan.py
MY_NETWORKS = {
    "MyHomeSSID": "aa:bb:cc:dd:ee:ff",
}

KNOWN_NETWORKS = {
    "Neighbor-WiFi": "11:22:33:44:55:66",
}
Usage Guide
Phase 1: Scanning with scan.py

This tool scans .pcap files for a wide range of threats.

To Run:

Bash
python scan.py
An interactive menu will appear. You can choose to scan the most recent file, all files, or select specific files to analyze.

Example Output:

🚨 Threats Detected in capture.pcap:
  - Deauthentication/Disassociation Flood (Count: 152)
  - Rogue AP: SSID 'MyHomeSSID' from unauthorized BSSID de:ad:be:ef:ca:fe (Count: 10)

💾 Saving threat evidence to 'warning_2025-06-16_18-30-00.pcap' and '.txt'...
✅ Successfully saved 162 packets to evidence/warning_2025-06-16_18-30-00.pcap
✅ Detailed report saved to evidence/warning_2025-06-16_18-30-00.txt
Phase 2: Analyzing Evidence with analyze_evidence.py

After generating evidence, use this tool to see who is attacking your networks.

To Run:

Bash
python analyze_evidence.py
The script will first confirm the networks it loaded from scan.py, then prompt you to select an evidence file.

Example Output:

📈 Analysis Complete: Unknown Devices Attacking YOUR Access Points
============================================================

🚨 Potential Attacker MAC: de:ad:be:ef:ca:fe
   - Total Packets Sent to Your APs: 10
   - Breakdown of Attack Types:
     - Rogue Access Points: 10 packets

------------------------------------------------------------
🧠 Generate an AI-powered mitigation report for these findings? (y/n): y
Phase 3: RF Fingerprinting with rfingertip.py

Use this tool for advanced analysis of potential MAC spoofing.

To Run:

Bash
python rfingertip.py
The GUI will launch. Use the "Choose Files" button to load one or more .pcap files. If suspicious clusters are found, plots will be displayed, and a rf_fingerprints_report.json file will be generated.

Understanding the Detections
Deauthentication/Disassociation Floods: A Denial-of-Service (DoS) attack where an attacker sends spoofed frames to disconnect clients from a network.
Rogue Access Point: An unauthorized AP broadcasting your network's SSID to trick users into connecting, enabling Man-in-the-Middle (MitM) attacks.
Evil Twin: A more advanced rogue AP that spoofs both the SSID and the MAC address (BSSID) of a legitimate AP. Our script detects this by finding an AP on multiple channels simultaneously.
ARP Spoofing: A Layer 3 attack where an attacker sends forged ARP messages to associate their MAC address with the IP address of another device (often the router), allowing them to intercept traffic.
DNS Spoofing: An attack where an attacker provides false DNS responses, redirecting a user to a malicious website instead of the legitimate one.
High Retransmissions: While not always malicious, a very high rate of retransmitted packets can indicate a jamming attack designed to disrupt network communication.
Troubleshooting
FileNotFoundError for wifi_pcap_regex.json or .env: Make sure these files exist in the same directory as the scripts you are running.
No .pcap files found: Ensure your capture files are located in the /var/tmp/ directory, or update the PCAP_DIRECTORY variable in the scripts. Also, check that the script has permission to read the directory.
AI Report Fails:
Verify that your API keys in the .env file are correct and have not expired.
Ensure your internet connection is active.
Check the AI provider's status page for any outages.
GUI (rfingertip.py) doesn't launch: Make sure you have installed all dependencies correctly, especially PyQt6.
Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. Please make sure to update tests as appropriate.

License
 This project is licensed under the MIT License.