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

# Scapy imports, including the pcap writer
from scapy.all import rdpcap, wrpcap, Dot11, Dot11Auth, Dot11Deauth, Dot11Disas, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, EAPOL, Dot11AssoReq, RadioTap, Dot11Elt, ARP, DNS, DHCP, BOOTP
from tqdm import tqdm
from pick import pick

# --- Configuration ---
PCAP_DIRECTORY = "/var/tmp/"
LOG_FILE = "wifi_threats.log"
DETECTIONS_FILE = "wifi_pcap_regex.json"
EVIDENCE_DIRECTORY = os.path.join(os.getcwd(), "evidence") # Save evidence in a sub-folder

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

# --- Helper Functions ---
def get_channel(packet):
    if packet.haslayer(RadioTap):
        try:
            if hasattr(packet[RadioTap], 'ChannelFrequency'):
                 freq = packet[RadioTap].ChannelFrequency
                 if 2400 < freq < 2500: return (freq - 2407) // 5
                 if 5000 < freq < 6000: return (freq - 5000) // 5
        except Exception: pass
    return None

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

# --- FIXED: Function to save evidence files with detailed descriptions ---
def save_evidence(threats_collection, original_pcap_name):
    """Saves detected rogue packets and a detailed summary report."""
    if not threats_collection:
        return

    if not os.path.exists(EVIDENCE_DIRECTORY):
        os.makedirs(EVIDENCE_DIRECTORY)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_filename = f"warning_{timestamp}"
    pcap_filename = os.path.join(EVIDENCE_DIRECTORY, f"{base_filename}.pcap")
    txt_filename = os.path.join(EVIDENCE_DIRECTORY, f"{base_filename}.txt")

    all_rogue_packets = []
    
    print(f"\n💾 Saving threat evidence to '{base_filename}.pcap' and '.txt'...")

    with open(txt_filename, 'w') as f:
        f.write(f"Wi-Fi Threat Scanner - Evidence Report\n")
        f.write(f"Source Capture: {original_pcap_name}\n")
        f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")

        for threat_desc, packets in sorted(threats_collection.items()):
            f.write(f"🚨 THREAT DETECTED: {threat_desc}\n")
            f.write(f"   Number of related packets found: {len(packets)}\n")
            f.write("--------------------------------------------------\n\n")
            
            for i, packet in enumerate(packets):
                all_rogue_packets.append(packet)
                
                f.write(f"--- Packet #{i+1} Summary: {packet.summary()} ---\n")
                # Capture the full, detailed output of packet.show()
                string_io = io.StringIO()
                with redirect_stdout(string_io):
                    packet.show()
                detailed_info = string_io.getvalue()
                f.write(detailed_info)
                f.write("-" * 20 + "\n\n")
            f.write("\n")

    # The wrpcap function can handle duplicate packets, but let's write them all
    if all_rogue_packets:
        wrpcap(pcap_filename, all_rogue_packets)
        print(f"✅ Successfully saved {len(all_rogue_packets)} packets to {pcap_filename}")
        print(f"✅ Detailed report saved to {txt_filename}")

# --- ALL THREAT DETECTION FUNCTIONS (YIELDING PACKETS) ---

# --- FIXED: Placeholder function no longer yields irrelevant packets ---
def placeholder_check(packets):
    """A placeholder for complex detections that are not yet implemented."""
    # This function now does nothing to prevent polluting the evidence file.
    yield from () # Yield an empty generator

def check_deauth_disas_floods(packets):
    deauth_packets = [p for p in packets if p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas)]
    if len(deauth_packets) > DEAUTH_FLOOD_THRESHOLD:
        for packet in deauth_packets:
            yield "Deauthentication/Disassociation Flood", packet

def check_auth_flood(packets):
    auth_requests_by_ap = defaultdict(list)
    for packet in packets:
        if packet.haslayer(Dot11Auth):
            auth_requests_by_ap[packet.addr1].append(packet)
    for ap, pkts in auth_requests_by_ap.items():
        if len(pkts) > AUTH_FLOOD_THRESHOLD:
            for packet in pkts:
                yield f"Authentication Flood on AP {ap}", packet

def check_rogue_access_points(packets):
    for packet in packets:
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            try:
                ssid = packet.info.decode('utf-8', 'ignore')
                bssid = packet.addr2
                if ssid and ssid in KNOWN_NETWORKS and KNOWN_NETWORKS[ssid].lower() != bssid.lower():
                    yield f"Rogue AP: SSID '{ssid}' from unauthorized BSSID {bssid}", packet
            except: continue

def check_wpa_handshake_capture(packets):
    handshakes = defaultdict(list)
    for packet in packets:
        if packet.haslayer(EAPOL):
            participants = tuple(sorted((packet.addr1, packet.addr2)))
            handshakes[participants].append(packet)
    for participants, pkts in handshakes.items():
        key_infos = {p[EAPOL].key_info for p in pkts if hasattr(p[EAPOL], 'key_info')}
        if len(key_infos) >= 2:
            for packet in pkts:
                yield f"WPA Handshake Capture between {participants[0]} and {participants[1]}", packet

def check_anomalous_probe_requests(packets):
    for pkt in packets:
        if pkt.haslayer(Dot11ProbeReq) and (not pkt.info or pkt.info == b'\x00'):
            yield f"Anomalous Null Probe Request from {pkt.addr2}", pkt
    
def check_malformed_beacon_frames(packets):
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            try:
                if len(pkt.info) > SSID_MAX_LENGTH:
                    yield f"Malformed Beacon: Long SSID from {pkt.addr2} (len: {len(pkt.info)})", pkt
            except: continue

def check_rts_cts_flood(packets):
    rts_cts_packets = [p for p in packets if p.haslayer(Dot11) and p.type == 1 and p.subtype in [11, 12]]
    if len(rts_cts_packets) > RTS_CTS_FLOOD_THRESHOLD:
        for packet in rts_cts_packets:
            yield "RTS/CTS Flood", packet

def check_evil_twin(packets):
    bssid_info = defaultdict(lambda: {'channels': set(), 'packets': []})
    for p in packets:
        if p.haslayer(Dot11) and hasattr(p, 'addr2') and p.addr2:
            channel = get_channel(p)
            if channel:
                bssid_info[p.addr2]['channels'].add(channel)
                bssid_info[p.addr2]['packets'].append(p)
    for bssid, info in bssid_info.items():
        if len(info['channels']) > 1:
            for packet in info['packets']:
                yield f"Evil Twin: BSSID {bssid} on multiple channels {info['channels']}", packet

def check_wps_bruteforce(packets):
    wps_failures = defaultdict(list)
    for pkt in packets:
        if pkt.haslayer(Dot11Elt) and pkt.ID == 221 and pkt.info.startswith(b'\x00P\xf2\x04'):
            if b'\x10\x49' in pkt.info and b'\x10\x27\x00\x01\x01' in pkt.info:
                participants = tuple(sorted((pkt.addr1, pkt.addr2)))
                wps_failures[participants].append(pkt)
    for p, pkts in wps_failures.items():
        if len(pkts) > WPS_FAILURE_THRESHOLD:
            for packet in pkts:
                yield f"WPS Brute-Force on {p[0]}/{p[1]}", packet

def check_pmkid_capture(packets):
    for p in packets:
        if p.haslayer(Dot11AssoReq):
            rsn = p.getlayer(Dot11Elt, ID=48)
            if rsn and b'PMKID' in rsn.info:
                yield f"PMKID Capture? from {p.addr2} to {p.addr1}", p

def check_karma_mana(packets):
    beaconed = defaultdict(set)
    for p in packets:
        if p.haslayer(Dot11Beacon):
            try: beaconed[p.addr2].add(p.info.decode())
            except: pass
    for p in packets:
        if p.haslayer(Dot11ProbeResp):
            try:
                ssid, bssid = p.info.decode(), p.addr2
                if ssid and ssid not in beaconed[bssid]:
                    yield f"Karma/MANA?: {bssid} for non-beaconed '{ssid}'", p
            except: pass

def check_hidden_ssid_decloak(packets):
    hidden_aps = {p.addr2 for p in packets if p.haslayer(Dot11Beacon) and not p.info}
    for p in packets:
        if p.haslayer(Dot11ProbeResp) and p.addr2 in hidden_aps:
            try:
                ssid = p.info.decode()
                if ssid:
                    yield f"Hidden SSID Decloaked: {p.addr2} is '{ssid}'", p
                    hidden_aps.remove(p.addr2)
            except: pass

def check_arp_spoofing(packets):
    ip_mac = {}
    for p in packets:
        if p.haslayer(ARP) and p[ARP].op == 2:
            ip, mac = p[ARP].psrc, p[ARP].hwsrc
            if ip in ip_mac and ip_mac[ip] != mac:
                yield f"ARP Spoofing?: {ip} was {ip_mac[ip]}, now {mac}", p
            ip_mac[ip] = mac

def check_dns_spoofing(packets):
    queries = defaultdict(list)
    query_responses = defaultdict(set)
    for p in packets:
        if p.haslayer(DNS):
            queries[p[DNS].id].append(p)
            if p[DNS].qr == 1:
                for i in range(p[DNS].ancount):
                    ans = p[DNS].an[i]
                    if hasattr(ans, 'type') and ans.type == 1:
                        query_responses[p[DNS].id].add(ans.rdata)
    for qid, ips in query_responses.items():
        if len(ips) > 1:
            for packet in queries[qid]:
                yield f"DNS Spoofing?: Query {qid} got conflicting IPs: {ips}", packet

def check_dhcp_starvation(packets):
    dhcp_discover_packets = [p for p in packets if p.haslayer(DHCP) and p[DHCP].options[0][1] == 1]
    if len({p[BOOTP].chaddr for p in dhcp_discover_packets}) > DHCP_DISCOVER_THRESHOLD:
        for packet in dhcp_discover_packets:
            yield "DHCP Starvation Attack", packet

def check_high_retransmissions(packets):
    retries = [p for p in packets if p.haslayer(Dot11) and hasattr(p.FCfield, 'retry') and p.FCfield.retry]
    if len(retries) > HIGH_RETRANS_THRESHOLD:
        for packet in retries:
            yield "High Retransmissions (Jamming?)", packet

def check_broadcast_storms(packets):
    bcast_packets = [p for p in packets if p.haslayer(Dot11) and hasattr(p, 'addr1') and p.addr1 and p.addr1.lower() == "ff:ff:ff:ff:ff:ff"]
    if len(bcast_packets) > BROADCAST_STORM_THRESHOLD:
        for packet in bcast_packets:
            yield "Broadcast Storm", packet

def check_location_profiling(packets):
    client_probes = defaultdict(list)
    client_ssids = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(Dot11ProbeReq) and pkt.info:
            try:
                ssid = pkt.info.decode()
                client_probes[pkt.addr2].append(pkt)
                client_ssids[pkt.addr2].add(ssid)
            except: continue
    for client, ssids in client_ssids.items():
        if len(ssids) > LOCATION_PROFILING_THRESHOLD:
            for packet in client_probes[client]:
                yield f"Location Profiling?: Client {client} probed for {len(ssids)} unique SSIDs", packet

def check_beacon_flood(packets):
    beaconing_bssid = defaultdict(list)
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            beaconing_bssid[pkt.addr2].append(pkt)
    if len(beaconing_bssid) > BEACON_FLOOD_THRESHOLD:
        for bssid, pkts in beaconing_bssid.items():
            for packet in pkts:
                yield "Beacon Flood", packet

check_client_mac_spoofing = check_arp_spoofing
check_ssid_broadcast_flooding = check_beacon_flood
check_cryptographic_downgrade = check_wpa_handshake_capture

# --- Master Detection Dispatcher ---
DETECTION_DISPATCHER = {
    "Deauthentication/Disassociation Floods": check_deauth_disas_floods,
    "Authentication Floods": check_auth_flood,
    "Rogue Access Points": check_rogue_access_points,
    "WPA Handshake Capture": check_wpa_handshake_capture,
    "Anomalous Probe Requests": check_anomalous_probe_requests,
    "Malformed Beacon Frames": check_malformed_beacon_frames,
    "Evil Twin Attacks": check_evil_twin,
    "ARP Spoofing": check_arp_spoofing,
    "DNS Spoofing": check_dns_spoofing,
    "Client MAC Spoofing": check_client_mac_spoofing,
    "SSID Broadcast Flooding": check_ssid_broadcast_flooding,
    "High Retransmissions": check_high_retransmissions,
    "DHCP Starvation": check_dhcp_starvation,
    "Broadcast Storms": check_broadcast_storms,
    "Location Profiling": check_location_profiling,
    "Cryptographic Downgrade Attacks": check_cryptographic_downgrade,
    "RTS/CTS Floods": check_rts_cts_flood,
    "Beacon Floods": check_beacon_flood,
    "WPS Brute-Force Indicators": check_wps_bruteforce,
    "PMKID Capture": check_pmkid_capture,
    "Hidden SSID Decloaking": check_hidden_ssid_decloak,
    "Karma/MANA Attack Indicators": check_karma_mana,
    # Placeholders for complex detections
    "Channel Congestion": placeholder_check,
    "Device Tracking via MAC/SSID Probing": placeholder_check,
    "Unexpected Protocol Usage": placeholder_check,
    "Suspicious Timing Patterns": placeholder_check,
    "Signal Strength Manipulation": placeholder_check,
}

# --- Main Application Logic ---
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

def run_pcap_analysis(pcap_files_to_scan, scan_plan):
    for pcap_file in pcap_files_to_scan:
        print("\n" + "=" * 60)
        print(f"📄 Scanning: {os.path.basename(pcap_file)}")
        try:
            packets = rdpcap(pcap_file)
        except Exception as e:
            print(f"❌ Error reading {os.path.basename(pcap_file)}: {e}")
            continue

        threats_collection = defaultdict(list)
        active_plan = [d for d in scan_plan if d.get("name") in DETECTION_DISPATCHER]
        scan_progress = tqdm(active_plan, desc="Running Checks", unit=" check", leave=False)
        
        for detection in scan_progress:
            check_name = detection["name"]
            scan_progress.set_description(f"Checking: {check_name}")
            check_function = DETECTION_DISPATCHER.get(check_name)
            if check_function:
                for threat_desc, packet in check_function(packets):
                    threats_collection[threat_desc].append(packet)
        scan_progress.close()

        print("-" * 60)
        if threats_collection:
            print(f"🚨 Threats Detected in {os.path.basename(pcap_file)}:")
            for threat, pkts in sorted(threats_collection.items()):
                log_message = f"  - {threat} (Count: {len(pkts)})"
                print(log_message)
                logging.warning(f"[{os.path.basename(pcap_file)}] {log_message}")
            save_evidence(threats_collection, os.path.basename(pcap_file))
        else:
            print(f"✅ No threats detected in {os.path.basename(pcap_file)}.")
        print("-" * 60)

def main():
    if not os.path.exists(EVIDENCE_DIRECTORY):
        os.makedirs(EVIDENCE_DIRECTORY)
        
    detections = load_detections_from_json(DETECTIONS_FILE)
    if detections is None:
        return

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print("🚀 Wi-Fi Threat Scanner 🚀")
        print("-" * 30)
        
        menu_title = "Please choose an action:"
        menu_options = [
            "Scan most recent file",
            "Scan ALL files in directory",
            "Select specific file(s) to scan",
            "Live Scan to define a legitimate AP (Linux only)",
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
            print("\nLive Scan feature is not implemented in this code block for brevity.")
            pass
        elif index == 4:
            print("👋 Exiting scanner. Goodbye!")
            break

        if pcap_files_to_process:
            run_pcap_analysis(pcap_files_to_process, detections)
        elif index in [0, 1, 2]:
             print(f"❌ No .pcap or .pcapng files found in {PCAP_DIRECTORY}")

        if index != 4:
            input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()