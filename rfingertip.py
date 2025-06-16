#!/usr/bin/env python3

import os
import json
import statistics
from collections import defaultdict
from datetime import datetime
import sys

# Scapy for packet reading
from scapy.all import RadioTap, Dot11
from pcap_utils import load_pcap_fast

# Matplotlib for plotting
import matplotlib.pyplot as plt

# PyQt6 for the GUI and threading
from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel, QMessageBox

# --- Utility Functions ---

def extract_packet_features(pkt):
    """
    Safely extracts MAC, timestamp, and RSSI from a packet.
    Returns None if the packet is invalid or missing required fields.
    """
    if not pkt.haslayer(RadioTap) or not pkt.haslayer(Dot11):
        return None

    try:
        # Use getattr for safe access to prevent crashes if the field is missing
        rssi = getattr(pkt, 'dBm_AntSignal', None)
        mac = pkt.addr2
        
        # Ensure we have all necessary features before proceeding
        if mac is None or rssi is None:
            return None

        # --- FIXED LINE ---
        # Explicitly convert Scapy's high-precision timestamp to a standard Python float
        timestamp = float(pkt.time)

        return mac, timestamp, rssi
    except Exception:
        return None

def group_by_mac(packets):
    """Groups packet features by their source MAC address."""
    grouped = defaultdict(list)
    for pkt in packets:
        features = extract_packet_features(pkt)
        if features:
            mac, ts, rssi = features
            grouped[mac].append((ts, rssi))
    return grouped


def analyze_grouped_data(grouped):
    """Calculates statistical fingerprints for each MAC address."""
    fingerprints = []
    for mac, samples in grouped.items():
        if len(samples) < 5:  # Require a minimum number of packets for a reliable fingerprint
            continue

        times = [s[0] for s in samples]
        rssis = [s[1] for s in samples]
        # Calculate Inter-Arrival Times (time between consecutive packets)
        iats = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])] if len(times) > 1 else []

        rssi_std = statistics.stdev(rssis) if len(rssis) > 1 else 0
        iat_std = statistics.stdev(iats) if len(iats) > 1 else 0

        fingerprints.append({
            'mac': mac,
            'count': len(samples),
            'rssi_std': round(rssi_std, 2),
            'iat_std': round(iat_std, 5),
            'first_seen': datetime.fromtimestamp(min(times)).isoformat(),
            'last_seen': datetime.fromtimestamp(max(times)).isoformat(),
            'timestamps': times,
            'rssis': rssis,
            'iats': iats
        })
    return fingerprints


def detect_similar_fingerprints(fingerprints, rssi_thresh=1.5, iat_thresh=0.05):
    """Clusters devices with similar RF fingerprints."""
    clusters = []
    for fp in fingerprints:
        matched = False
        for cluster in clusters:
            # Compare the new fingerprint to the first fingerprint in each existing cluster
            if abs(fp['rssi_std'] - cluster[0]['rssi_std']) < rssi_thresh and \
               abs(fp['iat_std'] - cluster[0]['iat_std']) < iat_thresh:
                cluster.append(fp)
                matched = True
                break
        if not matched:
            clusters.append([fp])
    # Return only clusters with more than one device, as these are suspicious
    return [c for c in clusters if len(c) > 1]


def visualize_fingerprints(clusters):
    """Generates and displays plots for each suspicious cluster."""
    if not clusters:
        # Return a value to indicate no plots were generated
        return False

    for i, cluster in enumerate(clusters):
        fig, axs = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
        cluster_macs = [fp['mac'] for fp in cluster]
        fig.suptitle(f"Suspicious Cluster #{i + 1}: {len(cluster_macs)} devices with similar RF fingerprints", fontsize=16)

        # Assign each MAC a different vertical line for the event plot
        mac_indices = {mac: i for i, mac in enumerate(cluster_macs)}

        for fp in cluster:
            if not fp['timestamps'] or not fp['rssis']:
                continue
            
            # Normalize timestamps to start from 0 for easier plotting
            start_time = fp['timestamps'][0]
            ts = [t - start_time for t in fp['timestamps']]
            
            # RSSI Time Series
            axs[0].plot(ts, fp['rssis'], marker='.', linestyle='-', label=fp['mac'])
            
            # Burst Timeline (Event Plot)
            # FIXED: Use lineoffsets to plot each device on its own line
            axs[1].eventplot(ts, orientation='horizontal', lineoffsets=mac_indices[fp['mac']], linelengths=0.8)

            # Inter-Packet Timing Histogram
            if fp['iats']:
                axs[2].hist(fp['iats'], bins=30, alpha=0.6, label=fp['mac'])

        axs[0].set_title("RSSI Time Series (Signal Strength vs. Time)")
        axs[0].set_ylabel("RSSI (dBm)")
        axs[0].grid(True)
        axs[0].legend()

        # FIXED: Set y-ticks to be the MAC addresses for clarity
        axs[1].set_title("Packet Burst Timeline")
        axs[1].set_yticks(list(mac_indices.values()))
        axs[1].set_yticklabels(list(mac_indices.keys()))

        axs[2].set_title("Inter-Packet Timing Histogram")
        axs[2].set_xlabel("Time Since First Packet (s)")
        axs[2].set_ylabel("Frequency")
        axs[2].grid(True)
        axs[2].legend()

        plt.tight_layout(rect=[0, 0, 1, 0.96])
        plt.show()
    return True

# --- Worker for Threaded Analysis ---
# FIXED: Moved analysis to a separate thread to keep the GUI responsive

class AnalysisWorker(QObject):
    """Performs the heavy lifting in a separate thread."""
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, filenames):
        super().__init__()
        self.filenames = filenames

    def run(self):
        """The main analysis logic."""
        try:
            all_packets = []
            for filename in self.filenames:
                all_packets.extend(load_pcap_fast(filename))
            
            if not all_packets:
                self.error.emit("No valid 802.11 packets found in the selected files.")
                return

            grouped = group_by_mac(all_packets)
            fingerprints = analyze_grouped_data(grouped)
            clusters = detect_similar_fingerprints(fingerprints)
            self.finished.emit(clusters)
        except Exception as e:
            self.error.emit(f"An unexpected error occurred during analysis: {e}")

# --- PyQt GUI ---
# FIXED: The GUI now manages the worker thread and responds to its signals

class RFAnalyzerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RF Fingerprinting Analyzer")
        self.setGeometry(100, 100, 400, 150)

        self.layout = QVBoxLayout()
        self.label = QLabel("Select one or more PCAP files to analyze.")
        self.layout.addWidget(self.label)

        self.btn = QPushButton("Choose Files")
        self.btn.clicked.connect(self.start_analysis)
        self.layout.addWidget(self.btn)

        self.setLayout(self.layout)

    def start_analysis(self):
        """Initiates the file selection and starts the worker thread."""
        filenames, _ = QFileDialog.getOpenFileNames(self, "Select PCAP files", "", "PCAP Files (*.pcap *.pcapng)")
        if not filenames:
            return

        self.btn.setEnabled(False)
        self.label.setText("Analyzing... This may take a moment.")

        # Create and start the worker thread
        self.thread = QThread()
        self.worker = AnalysisWorker(filenames)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_analysis_complete)
        self.worker.error.connect(self.on_analysis_error)
        
        # Clean up the thread when it's done
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        
        self.thread.start()

    def on_analysis_complete(self, clusters):
        """Handles the results when the analysis is finished."""
        self.label.setText(f"Analysis Complete! Found {len(clusters)} suspicious clusters.")
        
        output_filename = "rf_fingerprints_report.json"
        with open(output_filename, "w") as f:
            json.dump(clusters, f, indent=2)
        QMessageBox.information(self, "Success", f"Report saved to {output_filename}")

        if not visualize_fingerprints(clusters):
             QMessageBox.information(self, "No Clusters", "No suspicious clusters with multiple devices were found to visualize.")

        self.btn.setEnabled(True)

    def on_analysis_error(self, error_message):
        """Shows an error message if something went wrong."""
        QMessageBox.critical(self, "Analysis Error", error_message)
        self.label.setText("Analysis failed. Please try again.")
        self.btn.setEnabled(True)

# --- Main ---
def main():
    app = QApplication(sys.argv)
    window = RFAnalyzerApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()