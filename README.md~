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