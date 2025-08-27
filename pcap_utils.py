import os
import random

try:
    from scapy.all import RawPcapReader, RadioTap, Dot11, IP, TCP, UDP, Raw
except Exception:  # scapy may be stubbed in tests
    RawPcapReader = None
    RadioTap = None
    Dot11 = None
    IP = None
    TCP = None
    UDP = None
    Raw = None

def load_pcap_fast(pcap_path, max_packets=100000, sample_rate=1.0):
    """
    Efficiently load packets from a PCAP using dpkt if available.
    
    Args:
        pcap_path: Path to the PCAP file
        max_packets: Maximum number of packets to load
        sample_rate: Sampling rate (1.0 = all packets, 0.1 = 10% of packets)
    """
    try:
        file_size = os.path.getsize(pcap_path)
    except FileNotFoundError:
        print(f"❌ File not found: {pcap_path}")
        return []
    packets = []

    if RawPcapReader is None:
        return packets

    # Try the dpkt reader first for speed (much faster than RawPcapReader)
    try:
        import dpkt  # type: ignore
        print("🚀 Using fast dpkt reader...")
        
        # If sampling is enabled and file is large, use sampling
        if sample_rate < 1.0 and file_size > 50 * 1024 * 1024:  # 50MB
            print(f"📊 Using packet sampling (rate: {sample_rate:.1%}) for large file")
        
        with open(pcap_path, "rb") as f:
            for ts, buf in dpkt.pcap.Reader(f):
                # Apply sampling
                if sample_rate < 1.0 and random.random() > sample_rate:
                    continue
                    
                if len(packets) >= max_packets:
                    print(f"⚠️  Reached packet limit ({max_packets}), stopping analysis")
                    break
                try:
                    # Try to parse as RadioTap first (Wi-Fi packets)
                    pkt = RadioTap(buf)
                    # Only include packets that have Dot11 layer (actual Wi-Fi packets)
                    if pkt.haslayer(Dot11):
                        packets.append(pkt)
                except (Exception, RecursionError, MemoryError, KeyboardInterrupt):
                    # Skip packets we can't parse or that cause recursion
                    continue
        print(f"✅ Loaded {len(packets)} packets with dpkt")
        return packets
    except Exception as e:
        print(f"⚠️  dpkt failed, falling back to RawPcapReader: {e}")
        packets = []  # fall back to RawPcapReader

    # Fallback to RawPcapReader (slower but more reliable)
    try:
        try:
            from tqdm import tqdm
        except Exception:
            class Dummy:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    pass

                def update(self, *a, **k):
                    pass

            def tqdm(*a, **k):
                return Dummy()

        print("🔄 Using RawPcapReader (slower fallback)...")
        with RawPcapReader(pcap_path) as reader, tqdm(total=file_size, unit="B", unit_scale=True, desc="Reading PCAP") as bar:
            prev = 0
            for pkt_data, _ in reader:
                # Apply sampling
                if sample_rate < 1.0 and random.random() > sample_rate:
                    continue
                    
                if len(packets) >= max_packets:
                    print(f"⚠️  Reached packet limit ({max_packets}), stopping analysis")
                    break
                try:
                    # Try to parse as RadioTap first (Wi-Fi packets)
                    pkt = RadioTap(pkt_data)
                    # Only include packets that have Dot11 layer (actual Wi-Fi packets)
                    if pkt.haslayer(Dot11):
                        packets.append(pkt)
                except (Exception, RecursionError, MemoryError, KeyboardInterrupt):
                    # Skip packets we can't parse or that cause recursion
                    continue
                pos = getattr(reader, "offset", reader.f.tell())
                bar.update(pos - prev)
                prev = pos
        print(f"✅ Loaded {len(packets)} packets with RawPcapReader")
    except Exception as e:
        print(f"❌ Error reading {os.path.basename(pcap_path)}: {e}")
        return []

    return packets
