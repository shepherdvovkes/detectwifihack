# WiFi Threat Detection Summary

This document outlines all the malicious WiFi packet signs detected by both `scan.py` (Scapy-based) and `scan2.py` (TShark-based) scanners.

## Detection Capabilities

Both scanners detect the following categories of malicious WiFi activities:

### 1. **Deauthentication/Disassociation Floods**
- **Detection**: Counts deauthentication (subtype 12) and disassociation (subtype 10) packets
- **Threshold**: > 10 packets
- **Attack**: Disconnects clients from legitimate APs
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 12 or wlan.fc.subtype == 10`

### 2. **Authentication Floods**
- **Detection**: Counts authentication packets per AP
- **Threshold**: > 50 packets per AP
- **Attack**: Overwhelms AP authentication mechanisms
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 11`

### 3. **Beacon Floods**
- **Detection**: Counts beacon frames
- **Threshold**: > 100 beacons
- **Attack**: Creates fake APs or overwhelms channel
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 8`

### 4. **RTS/CTS Floods**
- **Detection**: Counts RTS/CTS control frames
- **Threshold**: > 200 packets
- **Attack**: Jams wireless communication
- **TShark Filter**: `wlan.fc.type == 1 and (wlan.fc.subtype == 11 or wlan.fc.subtype == 12)`

### 5. **WPA Handshake Capture**
- **Detection**: Identifies EAPOL packets with multiple key types
- **Threshold**: ≥ 4 EAPOL packets with ≥ 2 different types
- **Attack**: Captures WPA handshake for offline cracking
- **TShark Filter**: `eapol`

### 6. **Rogue Access Points**
- **Detection**: Compares SSID/BSSID against known networks
- **Attack**: Fake AP with legitimate SSID but different BSSID
- **TShark Filter**: Beacon frames with SSID analysis

### 7. **Anomalous Probe Requests**
- **Detection**: Null/empty SSID probe requests
- **Attack**: Hidden network discovery or scanning
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 4 and (wlan.ssid == "" or wlan.ssid == "\\x00")`

### 8. **Malformed Beacon Frames**
- **Detection**: SSID length > 32 characters
- **Attack**: Protocol manipulation or buffer overflow attempts
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 8 and length(wlan.ssid) > 32`

### 9. **Evil Twin Attacks**
- **Detection**: Same BSSID on multiple channels
- **Attack**: Fake AP on different channels
- **TShark Filter**: Beacon analysis with channel information

### 10. **ARP Spoofing**
- **Detection**: Conflicting IP-to-MAC mappings
- **Attack**: Man-in-the-middle attacks
- **TShark Filter**: `arp.opcode == 2`

### 11. **DNS Spoofing**
- **Detection**: Multiple IP responses for same DNS query
- **Attack**: Redirects traffic to malicious servers
- **TShark Filter**: `dns.flags.response == 1`

### 12. **DHCP Starvation**
- **Detection**: Multiple unique MAC addresses requesting IPs
- **Threshold**: > 50 unique clients
- **Attack**: Exhausts DHCP pool
- **TShark Filter**: `dhcp.option.dhcp == 1`

### 13. **High Retransmissions**
- **Detection**: Retransmitted frames
- **Threshold**: > 200 retransmissions
- **Attack**: Jamming or poor signal conditions
- **TShark Filter**: `wlan.fc.retry == 1`

### 14. **Broadcast Storms**
- **Detection**: Broadcast packets to ff:ff:ff:ff:ff:ff
- **Threshold**: > 500 packets
- **Attack**: Network flooding
- **TShark Filter**: `wlan.da == ff:ff:ff:ff:ff:ff`

### 15. **Location Profiling**
- **Detection**: Client probing for many unique SSIDs
- **Threshold**: > 20 unique SSIDs per client
- **Attack**: Tracks user movement patterns
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 4 and wlan.ssid != ""`

### 16. **WPS Brute-Force**
- **Detection**: WPS packets between same devices
- **Threshold**: > 5 packets
- **Attack**: Attempts to crack WPS PIN
- **TShark Filter**: `wlan.tag.vendor.oui == 00:50:f2 and wlan.tag.vendor.type == 4`

### 17. **PMKID Capture**
- **Detection**: Association requests with RSN IE
- **Attack**: Captures PMKID for offline cracking
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 0 and wlan.tag.number == 48`

### 18. **Hidden SSID Decloaking**
- **Detection**: Probe responses from hidden APs
- **Attack**: Reveals hidden network names
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 5 and wlan.ssid != ""`

### 19. **Karma/MANA Attacks**
- **Detection**: AP responding to probes for non-beaconed SSIDs
- **Attack**: Responds to any probe request
- **TShark Filter**: `wlan.fc.type == 0 and wlan.fc.subtype == 5`

## Configuration Thresholds

```python
DEAUTH_FLOOD_THRESHOLD = 10
AUTH_FLOOD_THRESHOLD = 50
BEACON_FLOOD_THRESHOLD = 100
RTS_CTS_FLOOD_THRESHOLD = 200
WPS_FAILURE_THRESHOLD = 5
DHCP_DISCOVER_THRESHOLD = 50
HIGH_RETRANS_THRESHOLD = 200
BROADCAST_STORM_THRESHOLD = 500
LOCATION_PROFILING_THRESHOLD = 20
SSID_MAX_LENGTH = 32
```

## Known Networks Configuration

Both scanners use the same known networks database:

```python
KNOWN_NETWORKS = {
    "0101001": "dc:62:79:7a:e6:f1",
    "TP-Link_5BA9_5G": "50:d4:f7:ee:5b:a8",
    "TP-Link_Guest_F5AF_5G": "b6:b0:24:3d:f5:b1",
    "Смурфик": "b4:b0:24:3d:f5:b1",
    "Goliath_5G": "00:31:92:1b:79:55",
    "Gryffindor_5G": "0a:bf:b8:f4:4a:8e",
}
```

## Key Differences Between Scanners

### scan.py (Scapy-based)
- **Pros**: 
  - Full packet manipulation capabilities
  - Detailed packet analysis
  - Custom packet crafting
  - Better for complex protocol analysis
- **Cons**: 
  - Slower processing
  - Higher memory usage
  - More complex code

### scan2.py (TShark-based)
- **Pros**: 
  - Faster processing
  - Lower memory usage
  - Leverages Wireshark's optimized packet parsing
  - Simpler implementation
- **Cons**: 
  - Limited to TShark's display filters
  - Less flexible for custom analysis
  - Requires TShark installation

## Evidence Collection

Both scanners save evidence in the same format:
- **PCAP files**: Extracted malicious packets
- **TXT files**: Detailed threat reports with packet summaries
- **Log files**: Timestamped threat detection logs

## Usage

```bash
# Run Scapy-based scanner
python3 scan.py

# Run TShark-based scanner
python3 scan2.py
```

Both scanners provide interactive menus for:
- Scanning most recent file
- Scanning all files in directory
- Selecting specific files to scan
- Evidence collection and reporting
