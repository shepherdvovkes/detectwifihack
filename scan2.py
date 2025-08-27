#!/usr/bin/env python3

import os
import glob
import logging
import subprocess
import json
from collections import defaultdict
from time import sleep
from datetime import datetime
import io
from contextlib import redirect_stdout
from concurrent.futures import ProcessPoolExecutor, as_completed, ThreadPoolExecutor
import multiprocessing
from functools import lru_cache
import time
from tqdm import tqdm
from pick import pick

# --- Configuration ---
PCAP_DIRECTORY = "/var/tmp/"
LOG_FILE = "wifi_threats_tshark.log"
DETECTIONS_FILE = "wifi_pcap_regex.json"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIRECTORY = os.path.join(SCRIPT_DIR, "evidence")

# -- Advanced Detection Thresholds --
DEAUTH_FLOOD_THRESHOLD = 10
AUTH_FLOOD_THRESHOLD = 50
BEACON_FLOOD_THRESHOLD = 100
RTS_CTS_FLOOD_THRESHOLD = 200
WPS_FAILURE_THRESHOLD = 5
SEQUENCE_NUMBER_JUMP = 1000
DHCP_DISCOVER_THRESHOLD = 50
HIGH_RETRANS_THRESHOLD = 200
BROADCAST_STORM_THRESHOLD = 500
LOCATION_PROFILING_THRESHOLD = 20
SSID_MAX_LENGTH = 32

# Performance settings
MAX_WORKERS = min(multiprocessing.cpu_count(), 8)  # Limit max workers
ENABLE_CACHING = True  # Enable caching for repeated operations

KNOWN_NETWORKS = {
    "0101001": "dc:62:79:7a:e6:f1",
    "TP-Link_5BA9_5G": "50:d4:f7:ee:5b:a8",
    "TP-Link_Guest_F5AF_5G": "b6:b0:24:3d:f5:b1",
    "Смурфик": "b4:b0:24:3d:f5:b1",
    "Goliath_5G": "00:31:92:1b:79:55",
    "Gryffindor_5G": "0a:bf:b8:f4:4a:8e",
}

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- TShark Detection Filters ---
TSHARK_DETECTIONS = {
    "Deauthentication/Disassociation Floods": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 12 or wlan.fc.subtype == 10",
        "threshold": DEAUTH_FLOOD_THRESHOLD,
        "description": "Deauthentication/Disassociation packets"
    },
    "Authentication Floods": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 11",
        "threshold": AUTH_FLOOD_THRESHOLD,
        "description": "Authentication packets"
    },
    "Beacon Floods": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 8",
        "threshold": BEACON_FLOOD_THRESHOLD,
        "description": "Beacon frames"
    },
    "RTS/CTS Floods": {
        "filter": "wlan.fc.type == 1 and (wlan.fc.subtype == 11 or wlan.fc.subtype == 12)",
        "threshold": RTS_CTS_FLOOD_THRESHOLD,
        "description": "RTS/CTS frames"
    },
    "WPA Handshake Capture": {
        "filter": "eapol",
        "threshold": 4,  # Need at least 4 EAPOL packets for handshake
        "description": "EAPOL packets (WPA handshake)"
    },
    "Anomalous Probe Requests": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 4 and (wlan.ssid == \"\" or wlan.ssid == \"\\x00\")",
        "threshold": 1,
        "description": "Null/empty SSID probe requests"
    },
    "Malformed Beacon Frames": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 8 and length(wlan.ssid) > 32",
        "threshold": 1,
        "description": "Beacon frames with SSID > 32 characters"
    },
    "High Retransmissions": {
        "filter": "wlan.fc.retry == 1",
        "threshold": HIGH_RETRANS_THRESHOLD,
        "description": "Retransmitted frames"
    },
    "Broadcast Storms": {
        "filter": "wlan.da == ff:ff:ff:ff:ff:ff",
        "threshold": BROADCAST_STORM_THRESHOLD,
        "description": "Broadcast packets"
    },
    "DHCP Starvation": {
        "filter": "dhcp.option.dhcp == 1",  # DHCP Discover
        "threshold": DHCP_DISCOVER_THRESHOLD,
        "description": "DHCP Discover packets"
    },
    "ARP Spoofing": {
        "filter": "arp.opcode == 2",  # ARP Reply
        "threshold": 1,
        "description": "ARP Reply packets"
    },
    "DNS Spoofing": {
        "filter": "dns.flags.response == 1",
        "threshold": 1,
        "description": "DNS Response packets"
    },
    "WPS Brute-Force Indicators": {
        "filter": "wlan.tag.vendor.oui == 00:50:f2 and wlan.tag.vendor.type == 4",
        "threshold": WPS_FAILURE_THRESHOLD,
        "description": "WPS packets"
    },
    "PMKID Capture": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 0 and wlan.tag.number == 48",
        "threshold": 1,
        "description": "Association requests with RSN IE"
    },
    "Hidden SSID Decloaking": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 5 and wlan.ssid != \"\"",
        "threshold": 1,
        "description": "Probe responses with SSID"
    },
    "Karma/MANA Attack Indicators": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 5",
        "threshold": 1,
        "description": "Probe response frames"
    },
    "Location Profiling": {
        "filter": "wlan.fc.type == 0 and wlan.fc.subtype == 4 and wlan.ssid != \"\"",
        "threshold": LOCATION_PROFILING_THRESHOLD,
        "description": "Probe requests with SSID"
    }
}

def run_tshark_command(pcap_file, display_filter, fields=None):
    """Run tshark command and return results."""
    cmd = ["tshark", "-r", pcap_file, "-Y", display_filter, "-T", "fields"]
    
    if fields:
        cmd.extend(["-e"] + fields)
    else:
        cmd.extend(["-e", "frame.number", "-e", "wlan.sa", "-e", "wlan.da", "-e", "wlan.ssid"])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        else:
            logging.error(f"TShark error: {result.stderr}")
            return []
    except subprocess.TimeoutExpired:
        logging.error(f"TShark timeout for file: {pcap_file}")
        return []
    except Exception as e:
        logging.error(f"TShark execution error: {e}")
        return []

def count_packets_with_filter(pcap_file, display_filter):
    """Count packets matching a filter."""
    cmd = ["tshark", "-r", pcap_file, "-Y", display_filter, "-q", "-z", "io,stat,0"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            # Parse the statistics output to get packet count
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if '|' in line and 'frames' in line.lower():
                    parts = line.split('|')
                    if len(parts) >= 2:
                        try:
                            return int(parts[1].strip())
                        except ValueError:
                            continue
        return 0
    except Exception as e:
        logging.error(f"Error counting packets: {e}")
        return 0

def detect_deauth_flood(pcap_file):
    """Detect deauthentication flood attacks."""
    count = count_packets_with_filter(pcap_file, TSHARK_DETECTIONS["Deauthentication/Disassociation Floods"]["filter"])
    if count > DEAUTH_FLOOD_THRESHOLD:
        return f"Deauthentication/Disassociation Flood: {count} packets detected"
    return None

def detect_auth_flood(pcap_file):
    """Detect authentication flood attacks."""
    # Get authentication packets with source addresses
    auth_packets = run_tshark_command(pcap_file, 
                                     TSHARK_DETECTIONS["Authentication Floods"]["filter"],
                                     ["wlan.sa", "wlan.da"])
    
    if not auth_packets:
        return None
    
    # Count auth packets per AP
    ap_counts = defaultdict(int)
    for line in auth_packets:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                ap = parts[1]  # wlan.da (destination AP)
                ap_counts[ap] += 1
    
    threats = []
    for ap, count in ap_counts.items():
        if count > AUTH_FLOOD_THRESHOLD:
            threats.append(f"Authentication Flood on AP {ap}: {count} packets")
    
    return threats if threats else None

def detect_rogue_access_points(pcap_file):
    """Detect rogue access points."""
    # Get beacon and probe response packets
    beacon_packets = run_tshark_command(pcap_file, 
                                       "wlan.fc.type == 0 and wlan.fc.subtype == 8",
                                       ["wlan.sa", "wlan.ssid"])
    
    threats = []
    for line in beacon_packets:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                bssid = parts[0]
                ssid = parts[1]
                
                if ssid in KNOWN_NETWORKS and KNOWN_NETWORKS[ssid].lower() != bssid.lower():
                    threats.append(f"Rogue AP: SSID '{ssid}' from unauthorized BSSID {bssid}")
    
    return threats if threats else None

def detect_wpa_handshake_capture(pcap_file):
    """Detect WPA handshake capture attempts."""
    eapol_packets = run_tshark_command(pcap_file, 
                                      TSHARK_DETECTIONS["WPA Handshake Capture"]["filter"],
                                      ["wlan.sa", "wlan.da", "eapol.type"])
    
    if not eapol_packets:
        return None
    
    # Group EAPOL packets by conversation
    conversations = defaultdict(list)
    for line in eapol_packets:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 3:
                sa, da, eapol_type = parts[0], parts[1], parts[2]
                conv_key = tuple(sorted([sa, da]))
                conversations[conv_key].append(eapol_type)
    
    threats = []
    for conv, types in conversations.items():
        if len(set(types)) >= 2:  # At least 2 different EAPOL types
            threats.append(f"WPA Handshake Capture between {conv[0]} and {conv[1]}: {len(types)} EAPOL packets")
    
    return threats if threats else None

def detect_evil_twin(pcap_file):
    """Detect evil twin attacks (same BSSID on multiple channels)."""
    beacon_packets = run_tshark_command(pcap_file, 
                                       "wlan.fc.type == 0 and wlan.fc.subtype == 8",
                                       ["wlan.sa", "wlan_radio.channel"])
    
    if not beacon_packets:
        return None
    
    # Group by BSSID and collect channels
    bssid_channels = defaultdict(set)
    for line in beacon_packets:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                bssid = parts[0]
                try:
                    channel = int(parts[1])
                    bssid_channels[bssid].add(channel)
                except ValueError:
                    continue
    
    threats = []
    for bssid, channels in bssid_channels.items():
        if len(channels) > 1:
            threats.append(f"Evil Twin: BSSID {bssid} on multiple channels {channels}")
    
    return threats if threats else None

def detect_arp_spoofing(pcap_file):
    """Detect ARP spoofing attacks."""
    arp_replies = run_tshark_command(pcap_file, 
                                    TSHARK_DETECTIONS["ARP Spoofing"]["filter"],
                                    ["arp.src.proto_ipv4", "arp.src.hw_mac"])
    
    if not arp_replies:
        return None
    
    # Track IP to MAC mappings
    ip_mac = {}
    threats = []
    
    for line in arp_replies:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                
                if ip in ip_mac and ip_mac[ip] != mac:
                    threats.append(f"ARP Spoofing: {ip} was {ip_mac[ip]}, now {mac}")
                ip_mac[ip] = mac
    
    return threats if threats else None

def detect_dns_spoofing(pcap_file):
    """Detect DNS spoofing attacks."""
    dns_responses = run_tshark_command(pcap_file, 
                                      TSHARK_DETECTIONS["DNS Spoofing"]["filter"],
                                      ["dns.id", "dns.a"])
    
    if not dns_responses:
        return None
    
    # Group responses by query ID
    query_responses = defaultdict(set)
    for line in dns_responses:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                query_id = parts[0]
                ip = parts[1]
                if ip:  # Only add non-empty IPs
                    query_responses[query_id].add(ip)
    
    threats = []
    for query_id, ips in query_responses.items():
        if len(ips) > 1:
            threats.append(f"DNS Spoofing: Query {query_id} got conflicting IPs: {ips}")
    
    return threats if threats else None

def detect_dhcp_starvation(pcap_file):
    """Detect DHCP starvation attacks."""
    dhcp_discovers = run_tshark_command(pcap_file, 
                                       TSHARK_DETECTIONS["DHCP Starvation"]["filter"],
                                       ["dhcp.client.hw_mac"])
    
    if not dhcp_discovers:
        return None
    
    # Count unique MAC addresses
    unique_macs = set()
    for line in dhcp_discovers:
        if line.strip():
            mac = line.strip()
            if mac:
                unique_macs.add(mac)
    
    if len(unique_macs) > DHCP_DISCOVER_THRESHOLD:
        return f"DHCP Starvation Attack: {len(unique_macs)} unique clients requesting IPs"
    
    return None

def detect_location_profiling(pcap_file):
    """Detect location profiling via probe requests."""
    probe_requests = run_tshark_command(pcap_file, 
                                       TSHARK_DETECTIONS["Location Profiling"]["filter"],
                                       ["wlan.sa", "wlan.ssid"])
    
    if not probe_requests:
        return None
    
    # Group by client MAC and count unique SSIDs
    client_ssids = defaultdict(set)
    for line in probe_requests:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                client_mac = parts[0]
                ssid = parts[1]
                if ssid:
                    client_ssids[client_mac].add(ssid)
    
    threats = []
    for client, ssids in client_ssids.items():
        if len(ssids) > LOCATION_PROFILING_THRESHOLD:
            threats.append(f"Location Profiling: Client {client} probed for {len(ssids)} unique SSIDs")
    
    return threats if threats else None

def detect_wps_bruteforce(pcap_file):
    """Detect WPS brute force attempts."""
    wps_packets = run_tshark_command(pcap_file, 
                                    TSHARK_DETECTIONS["WPS Brute-Force Indicators"]["filter"],
                                    ["wlan.sa", "wlan.da"])
    
    if not wps_packets:
        return None
    
    # Count WPS packets per conversation
    conv_counts = defaultdict(int)
    for line in wps_packets:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                conv_key = tuple(sorted([parts[0], parts[1]]))
                conv_counts[conv_key] += 1
    
    threats = []
    for conv, count in conv_counts.items():
        if count > WPS_FAILURE_THRESHOLD:
            threats.append(f"WPS Brute-Force: {count} packets between {conv[0]} and {conv[1]}")
    
    return threats if threats else None

def detect_pmkid_capture(pcap_file):
    """Detect PMKID capture attempts."""
    assoc_requests = run_tshark_command(pcap_file, 
                                       TSHARK_DETECTIONS["PMKID Capture"]["filter"],
                                       ["wlan.sa", "wlan.da"])
    
    if assoc_requests:
        return f"PMKID Capture: {len(assoc_requests)} association requests with RSN IE detected"
    
    return None

def detect_hidden_ssid_decloak(pcap_file):
    """Detect hidden SSID decloaking."""
    # First find hidden APs (beacons with empty SSID)
    hidden_beacons = run_tshark_command(pcap_file, 
                                       "wlan.fc.type == 0 and wlan.fc.subtype == 8 and (wlan.ssid == \"\" or wlan.ssid == \"\\x00\")",
                                       ["wlan.sa"])
    
    if not hidden_beacons:
        return None
    
    hidden_aps = set()
    for line in hidden_beacons:
        if line.strip():
            hidden_aps.add(line.strip())
    
    # Now check for probe responses from these APs
    probe_responses = run_tshark_command(pcap_file, 
                                        "wlan.fc.type == 0 and wlan.fc.subtype == 5",
                                        ["wlan.sa", "wlan.ssid"])
    
    threats = []
    for line in probe_responses:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                bssid = parts[0]
                ssid = parts[1]
                if bssid in hidden_aps and ssid:
                    threats.append(f"Hidden SSID Decloaked: {bssid} is '{ssid}'")
    
    return threats if threats else None

def detect_karma_mana(pcap_file):
    """Detect Karma/MANA attacks."""
    # Get all beacon frames with their SSIDs
    beacons = run_tshark_command(pcap_file, 
                                "wlan.fc.type == 0 and wlan.fc.subtype == 8",
                                ["wlan.sa", "wlan.ssid"])
    
    beaconed_ssids = defaultdict(set)
    for line in beacons:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                bssid = parts[0]
                ssid = parts[1]
                if ssid:
                    beaconed_ssids[bssid].add(ssid)
    
    # Get probe responses
    probe_responses = run_tshark_command(pcap_file, 
                                        "wlan.fc.type == 0 and wlan.fc.subtype == 5",
                                        ["wlan.sa", "wlan.ssid"])
    
    threats = []
    for line in probe_responses:
        if line.strip():
            parts = line.split('\t')
            if len(parts) >= 2:
                bssid = parts[0]
                ssid = parts[1]
                if ssid and bssid in beaconed_ssids and ssid not in beaconed_ssids[bssid]:
                    threats.append(f"Karma/MANA Attack: {bssid} responding to probe for '{ssid}' but not beaconing it")
    
    return threats if threats else None

def detect_basic_threats(pcap_file):
    """Detect basic threats using simple packet counting."""
    threats = []
    
    # Check various thresholds
    for threat_name, config in TSHARK_DETECTIONS.items():
        if "threshold" in config:
            count = count_packets_with_filter(pcap_file, config["filter"])
            if count > config["threshold"]:
                threats.append(f"{threat_name}: {count} packets (threshold: {config['threshold']})")
    
    return threats

def save_evidence_tshark(threats_collection, original_pcap_name):
    """Save detected threats to evidence files using tshark."""
    if not threats_collection:
        return

    if not os.path.exists(EVIDENCE_DIRECTORY):
        os.makedirs(EVIDENCE_DIRECTORY)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    base_filename = f"warning_tshark_{timestamp}"
    pcap_filename = os.path.join(EVIDENCE_DIRECTORY, f"{base_filename}.pcap")
    txt_filename = os.path.join(EVIDENCE_DIRECTORY, f"{base_filename}.txt")

    print(f"\n💾 Saving threat evidence to '{base_filename}.pcap' and '.txt'...")

    with open(txt_filename, 'w') as f:
        f.write(f"Wi-Fi Threat Scanner (TShark) - Evidence Report\n")
        f.write(f"Source Capture: {original_pcap_name}\n")
        f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")

        for threat_desc in threats_collection:
            f.write(f"🚨 THREAT DETECTED: {threat_desc}\n")
            f.write("--------------------------------------------------\n\n")

    # Extract packets for each threat type and save to pcap
    for threat_desc in threats_collection:
        # Determine appropriate filter based on threat description
        filter_map = {
            "Deauthentication": "wlan.fc.type == 0 and wlan.fc.subtype == 12 or wlan.fc.subtype == 10",
            "Authentication": "wlan.fc.type == 0 and wlan.fc.subtype == 11",
            "Beacon": "wlan.fc.type == 0 and wlan.fc.subtype == 8",
            "EAPOL": "eapol",
            "Probe": "wlan.fc.type == 0 and wlan.fc.subtype == 4",
            "ARP": "arp.opcode == 2",
            "DNS": "dns.flags.response == 1",
            "DHCP": "dhcp.option.dhcp == 1",
            "WPS": "wlan.tag.vendor.oui == 00:50:f2",
            "RTS/CTS": "wlan.fc.type == 1 and (wlan.fc.subtype == 11 or wlan.fc.subtype == 12)",
            "Broadcast": "wlan.da == ff:ff:ff:ff:ff:ff",
            "Retransmission": "wlan.fc.retry == 1"
        }
        
        # Find matching filter
        matching_filter = None
        for key, filter_str in filter_map.items():
            if key.lower() in threat_desc.lower():
                matching_filter = filter_str
                break
        
        if matching_filter:
            # Extract packets using tshark
            cmd = ["tshark", "-r", os.path.join(PCAP_DIRECTORY, original_pcap_name), 
                   "-Y", matching_filter, "-w", pcap_filename]
            try:
                subprocess.run(cmd, capture_output=True, timeout=60)
            except Exception as e:
                logging.error(f"Error extracting packets for {threat_desc}: {e}")

    print(f"✅ Evidence saved to {pcap_filename}")
    print(f"✅ Detailed report saved to {txt_filename}")

def load_detections_from_json(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return [d for d in data.get("detections", []) if d.get("enabled", True)]
    except FileNotFoundError:
        print(f"❌ Critical Error: Detection file not found at '{file_path}'")
        return None
    except json.JSONDecodeError:
        print(f"❌ Critical Error: Could not parse the JSON in '{file_path}'")
        return None

def get_pcap_files(directory):
    all_files = []
    try:
        for filename in os.listdir(directory):
            if filename.lower().endswith(('.pcap', '.pcapng')):
                full_path = os.path.join(directory, filename)
                all_files.append(full_path)
    except FileNotFoundError:
        print(f"Directory not found: {directory}")
        return []
    except PermissionError:
        print(f"Permission denied to read directory: {directory}")
        return []

    if not all_files:
        return []
    
    return sorted(all_files, key=os.path.getmtime, reverse=True)

def _process_single_pcap_tshark(pcap_file, scan_plan):
    """Helper for multiprocessing: analyze one pcap file using tshark."""
    start_time = time.time()
    output_lines = []
    output_lines.append("\n" + "=" * 60)
    output_lines.append(f"📄 Scanning: {os.path.basename(pcap_file)} (TShark)")

    print(f"🔄 Analyzing packets from {os.path.basename(pcap_file)} with TShark...")
    
    threats_collection = []
    
    # Run all detection functions
    detection_functions = [
        detect_deauth_flood,
        detect_auth_flood,
        detect_rogue_access_points,
        detect_wpa_handshake_capture,
        detect_evil_twin,
        detect_arp_spoofing,
        detect_dns_spoofing,
        detect_dhcp_starvation,
        detect_location_profiling,
        detect_wps_bruteforce,
        detect_pmkid_capture,
        detect_hidden_ssid_decloak,
        detect_karma_mana,
        detect_basic_threats
    ]
    
    for detection_func in detection_functions:
        try:
            result = detection_func(pcap_file)
            if result:
                if isinstance(result, list):
                    threats_collection.extend(result)
                else:
                    threats_collection.append(result)
        except Exception as e:
            logging.error(f"Error in detection function {detection_func.__name__}: {e}")

    processing_time = time.time() - start_time
    output_lines.append("-" * 60)
    if threats_collection:
        output_lines.append(f"🚨 Threats Detected in {os.path.basename(pcap_file)}:")
        for threat in threats_collection:
            log_message = f"  - {threat}"
            output_lines.append(log_message)
            logging.warning(f"[{os.path.basename(pcap_file)}] {log_message}")
        save_evidence_tshark(threats_collection, os.path.basename(pcap_file))
    else:
        output_lines.append(f"✅ No threats detected in {os.path.basename(pcap_file)}.")
    output_lines.append(f"⏱️  Processing time: {processing_time:.2f} seconds")
    output_lines.append("-" * 60)
    return "\n".join(output_lines)

def run_pcap_analysis_tshark(pcap_files_to_scan, scan_plan):
    if len(pcap_files_to_scan) > 1:
        max_workers = min(multiprocessing.cpu_count(), len(pcap_files_to_scan))
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_process_single_pcap_tshark, f, scan_plan) for f in pcap_files_to_scan]
            for future in as_completed(futures):
                print(future.result())
    else:
        result = _process_single_pcap_tshark(pcap_files_to_scan[0], scan_plan)
        print(result)

def main():
    if not os.path.exists(EVIDENCE_DIRECTORY):
        os.makedirs(EVIDENCE_DIRECTORY)
        
    detections = load_detections_from_json(DETECTIONS_FILE)
    if detections is None:
        return

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print("🚀 Wi-Fi Threat Scanner (TShark) 🚀")
        print("-" * 40)
        
        menu_title = "Please choose an action:"
        menu_options = [
            "Scan most recent file",
            "Scan ALL files in directory",
            "Select specific file(s) to scan",
            "Exit"
        ]
        
        option, index = pick(menu_options, menu_title, indicator='=>')

        pcap_files_to_process = []
        if index == 0:
            all_files = get_pcap_files(PCAP_DIRECTORY)
            if all_files: pcap_files_to_process = [all_files[0]]
        elif index == 1:
            pcap_files_to_process = get_pcap_files(PCAP_DIRECTORY)
        elif index == 2:
            all_files = get_pcap_files(PCAP_DIRECTORY)
            if all_files:
                try:
                    selected_items = pick(
                        [os.path.basename(f) for f in all_files],
                        "Select files with SPACE, press ENTER to confirm",
                        multiselect=True, min_selection_count=1
                    )
                    if selected_items:
                        pcap_files_to_process = [os.path.join(PCAP_DIRECTORY, item[0]) for item in selected_items]
                except Exception:
                    print("Menu selection cancelled.")
            else:
                print("No files found to select.")
        elif index == 3:
            print("👋 Exiting scanner. Goodbye!")
            break

        if pcap_files_to_process:
            run_pcap_analysis_tshark(pcap_files_to_process, detections)
        elif index in [0, 1, 2]:
             print(f"❌ No .pcap or .pcapng files found in {PCAP_DIRECTORY}")

        if index != 3:
            input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()
