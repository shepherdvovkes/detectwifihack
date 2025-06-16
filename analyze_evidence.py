#!/usr/bin/env python3

import os
import re
import ast
from collections import defaultdict
from datetime import datetime

# Environment and AI library imports
from dotenv import load_dotenv
import openai
import anthropic

# Scapy is used for packet analysis
from scapy.all import (
    Dot11,
    Dot11Deauth,
    Dot11Disas,
    Dot11Auth,
    Dot11ProbeReq,
    PcapReader,
)

# Pick is used for the interactive menu
from pick import pick

# --- Configuration ---
SCANNER_FILE_PATH = "scan.py"
EVIDENCE_DIRECTORY = "evidence"
AI_REPORTS_DIRECTORY = "ai_reports"

# --- AI Report Generation ---

def format_prompt_for_ai(attack_summary):
    """Formats the detected threats into a clear text prompt for the AI."""
    prompt_header = "You are a cybersecurity expert. Give concisely answers how to mitigate this type of wifi attack. Print no code only recommendations for the following detected threats:\n"
    
    # Consolidate threat names to avoid redundancy
    threat_types = set()
    for attacker_data in attack_summary.values():
        for threat_type in attacker_data['packet_types'].keys():
            threat_types.add(threat_type)
            
    if not threat_types:
        return None

    threat_list = "\n".join(f"- {threat}" for threat in sorted(list(threat_types)))
    return prompt_header + threat_list

def get_ai_report(prompt, provider):
    """Sends the prompt to the chosen AI provider and returns the report."""
    load_dotenv()
    
    try:
        if provider == "OpenAI":
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                print("❌ OPENAI_API_KEY not found in .env file.")
                return None
            client = openai.OpenAI(api_key=api_key)
            print("🤖 Asking OpenAI for mitigation advice...")
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content

        elif provider == "Anthropic":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                print("❌ ANTHROPIC_API_KEY not found in .env file.")
                return None
            client = anthropic.Anthropic(api_key=api_key)
            print("🤖 Asking Anthropic for mitigation advice...")
            # Separate system prompt and user message for Anthropic
            system_prompt, user_prompt = prompt.split("\n", 1)
            response = client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=1024,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )
            return response.content[0].text

    except Exception as e:
        print(f"❌ An error occurred while contacting the AI provider: {e}")
        return None

def save_ai_report(report_content):
    """Saves the generated AI report to a timestamped file."""
    if not os.path.exists(AI_REPORTS_DIRECTORY):
        os.makedirs(AI_REPORTS_DIRECTORY)
        
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = os.path.join(AI_REPORTS_DIRECTORY, f"ai_report_{timestamp}.txt")
    
    with open(report_filename, 'w') as f:
        f.write(report_content)
        
    print(f"\n✅ AI report saved successfully to: {report_filename}")

# --- Local Analysis Functions (Unchanged) ---

def load_known_networks_from_scanner(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            match = re.search(r"KNOWN_NETWORKS\s*=\s*({.*?})", content, re.DOTALL)
            if match:
                return ast.literal_eval(match.group(1))
            return None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"An error occurred while parsing {file_path}: {e}")
        return None

def get_packet_type(packet):
    if packet.haslayer(Dot11Deauth): return "Deauthentication Flood"
    if packet.haslayer(Dot11Disas): return "Disassociation"
    if packet.haslayer(Dot11Auth): return "Authentication Flood"
    if packet.haslayer(Dot11ProbeReq): return "Anomalous Probe Request"
    return "Generic Malicious Traffic"

def analyze_evidence_file(pcap_path, known_ap_bssids):
    attackers = defaultdict(lambda: {
        'count': 0,
        'packet_types': defaultdict(int)
    })

    try:
        with PcapReader(pcap_path) as reader:
            for packet in reader:
                if (
                    packet.haslayer(Dot11)
                    and hasattr(packet, 'addr1')
                    and packet.addr1 in known_ap_bssids
                ):
                    attacker_mac = packet.addr2
                    if attacker_mac in known_ap_bssids:
                        continue
                    attackers[attacker_mac]['count'] += 1
                    attackers[attacker_mac]['packet_types'][
                        get_packet_type(packet)
                    ] += 1
    except Exception as e:
        print(f"❌ Error reading pcap file: {e}")
        return None

    return attackers

def display_results(attackers):
    print("\n" + "="*50)
    print("📈 Local Analysis Complete: Attackers Targeting Your APs")
    print("="*50)

    if not attackers:
        print("✅ No packets were found targeting your known APs in this evidence file.")
        return

    sorted_attackers = sorted(attackers.items(), key=lambda item: item[1]['count'], reverse=True)
    for attacker_mac, data in sorted_attackers:
        print(f"\n🚨 Attacker MAC: {attacker_mac}")
        print(f"   - Total Packets Sent to Your APs: {data['count']}")
        print(f"   - Breakdown of Attack Types:")
        for pkt_type, count in data['packet_types'].items():
            print(f"     - {pkt_type}: {count} packets")

# --- Main Application Logic ---

def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    print("🚀 Wi-Fi Evidence Analyzer 🚀")
    print("-" * 30)

    known_networks = load_known_networks_from_scanner(SCANNER_FILE_PATH)
    if not known_networks:
        print(f"❌ Could not find KNOWN_NETWORKS in '{SCANNER_FILE_PATH}'.")
        return
    known_ap_bssids = set(known_networks.values())

    try:
        evidence_files = sorted([f for f in os.listdir(EVIDENCE_DIRECTORY) if f.lower().endswith('.pcap')])
    except FileNotFoundError:
        print(f"\n❌ Evidence directory '{EVIDENCE_DIRECTORY}' not found.")
        return

    if not evidence_files:
        print(f"\n❌ No .pcap files found in the '{EVIDENCE_DIRECTORY}' directory.")
        return
    
    title = "Please select an evidence file to analyze:"
    try:
        selected_file, index = pick(evidence_files, title, indicator='=>')
        full_pcap_path = os.path.join(EVIDENCE_DIRECTORY, selected_file)
    except Exception:
        print("\nSelection cancelled. Exiting.")
        return

    attack_summary = analyze_evidence_file(full_pcap_path, known_ap_bssids)

    if attack_summary is not None:
        display_results(attack_summary)
        
        # --- NEW AI Report Generation Step ---
        if attack_summary:
            print("-" * 50)
            generate_report = input("🧠 Generate an AI-powered mitigation report for these findings? (y/n): ").lower()
            if generate_report == 'y':
                ai_prompt = format_prompt_for_ai(attack_summary)
                if not ai_prompt:
                    print("Could not formulate a prompt from the findings.")
                    return

                provider, _ = pick(["OpenAI", "Anthropic"], "Choose an AI provider:", indicator="=>")
                
                ai_report = get_ai_report(ai_prompt, provider)
                
                if ai_report:
                    print("\n--- AI Mitigation Report ---")
                    print(ai_report)
                    print("--------------------------")
                    save_ai_report(ai_report)

if __name__ == "__main__":
    main()
