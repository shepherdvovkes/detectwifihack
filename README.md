\# Wi-Fi Security Analysis Toolkit

This project is a suite of Python tools designed for capturing, analyzing, and reporting on Wi-Fi network traffic to identify potential security threats, malicious behavior, and anomalies. It combines rule-based threat detection from `.pcap` files, evidence analysis, AI-powered mitigation reporting, and RF fingerprinting to provide a comprehensive security overview.

## Features

- **Data-Driven Threat Detection**: Utilizes a configurable JSON file (`wifi_pcap_regex.json`) to define and enable a wide range of threat detection rules.
- **Automated Evidence Collection**: Automatically saves malicious packets from a scan into a separate `.pcap` file and generates a detailed text report.
- **Targeted Attack Analysis**: A dedicated tool (`analyze_evidence.py`) to analyze evidence files and identify which unknown devices are targeting your personal networks.
- **AI-Powered Mitigation Reports**: Integrates with OpenAI and Anthropic APIs to generate expert recommendations on how to mitigate the detected threats.
- **RF Fingerprinting**: A GUI-based tool (`rfingertip.py`) to analyze packet timings and signal strength, clustering devices with similar hardware characteristics to potentially identify MAC address spoofing.
- **Interactive Interfaces**: User-friendly command-line and GUI interfaces for easy operation.

## Project Components

The toolkit is composed of several key files and directories:

| File / Directory            | Description                                                                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `scan.py`                   | The main threat scanner. It analyzes `.pcap` files in `/var/tmp/` based on rules in the JSON file and saves evidence of threats.             |
| `analyze_evidence.py`         | A post-analysis tool that examines saved evidence files to report on which devices are attacking your specific networks.               |
| `rfingertip.py`               | A PyQt6 GUI application for RF fingerprinting analysis to detect potential MAC spoofing.                                                 |
| `wifi_pcap_regex.json`      | **Required.** The configuration file that defines all detection rules for `scan.py`. You can enable or disable rules here.             |
| `.env`                        | **Required.** A local file (not committed to Git) that must contain your `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` for the AI features.   |
| `.gitignore`                | Ensures that sensitive files (`.env`) and generated directories are not committed to the Git repository.                                   |
| `evidence/`                   | Automatically created directory where `.pcap` and `.txt` evidence files are saved by `scan.py`.                                          |
| `ai_reports/`                 | Automatically created directory where AI-generated mitigation reports are saved by `analyze_evidence.py`.                               |

## Setup and Installation

Follow these steps to set up the project environment.

**1. Prerequisites**
- Python 3.8+
- `git`

**2. Clone the Repository**
```bash
# If you have it on GitHub
git clone [your-repository-url]
cd detectwifihack

3. Create and Activate a Virtual Environment

Bash
# Create the virtual environment
python3 -m venv venv

# Activate it (macOS/Linux)
source venv/bin/activate
4. Install Dependencies
A requirements.txt file is recommended for managing dependencies. Create a file named requirements.txt with the following content:

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
Then, install all dependencies at once:

Bash
pip install -r requirements.txt
5. Set Up API Keys
Create a file named .env in the root of the project directory. Add your API keys like so:

Code snippet
OPENAI_API_KEY="sk-..."
ANTHROPIC_API_KEY="sk-ant-..."
This file is already listed in .gitignore and will not be committed.

6. Configure Your Networks
Open scan.py and modify the MY_NETWORKS dictionary to include your personal, trusted Access Points. This is critical for accurate "Rogue AP" and targeted attack analysis.

Python
# In scan.py
MY_NETWORKS = {
    "Your_Home_SSID": "aa:bb:cc:dd:ee:ff",
    "Your_Office_SSID": "11:22:33:44:55:66"
}
Usage Workflow
1. Run the Main Scanner (scan.py)

This is your primary tool for analyzing .pcap files found in /var/tmp/.

Bash
python scan.py
The script will present a menu with several options:

Scan most recent file: A quick scan of the newest .pcap file.
Scan ALL files: Scans all .pcap files in the directory.
Select specific file(s) to scan: An interactive menu to choose one or more files to analyze.
If threats are found, evidence will be automatically saved to the evidence/ directory.

2. Analyze Threat Evidence (analyze_evidence.py)

After scan.py has generated evidence files, use this tool to get a focused report on who is attacking your networks.

Bash
python analyze_evidence.py
It will guide you through:

Loading your MY_NETWORKS configuration from scan.py.
Choosing an evidence file from the evidence/ directory.
Displaying a summary of unknown devices that sent malicious packets to your APs.
Optionally generating and saving an AI-powered mitigation report to the ai_reports/ folder.
3. Perform RF Fingerprinting (rfingertip.py)

This tool helps identify potential MAC address spoofing by analyzing physical-layer characteristics of Wi-Fi packets.

Bash
python rfingertip.py
A GUI window will appear. Click "Choose Files" to select one or more .pcap files. The application will:

Analyze the signal strength and packet timing for each device.
Cluster devices that have nearly identical "fingerprints."
Generate plots visualizing these suspicious clusters.
Save a detailed report as rf_fingerprints_report.json.
Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

License
 MIT
