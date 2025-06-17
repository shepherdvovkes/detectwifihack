import os

try:
    from scapy.all import RawPcapReader, RadioTap
except Exception:  # scapy may be stubbed in tests
    RawPcapReader = None
    RadioTap = None

def load_pcap_fast(pcap_path):
    """Efficiently load packets from a PCAP using RawPcapReader."""
    try:
        file_size = os.path.getsize(pcap_path)
    except FileNotFoundError:
        print(f"❌ File not found: {pcap_path}")
        return []
    packets = []

    if RawPcapReader is None or RadioTap is None:
        return packets

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

        with RawPcapReader(pcap_path) as reader, tqdm(total=file_size, unit="B", unit_scale=True, desc="Reading PCAP") as bar:
            prev = 0
            for pkt_data, _ in reader:
                try:
                    pkt = RadioTap(pkt_data)
                except Exception:
                    continue
                packets.append(pkt)
                pos = getattr(reader, "offset", reader.f.tell())
                bar.update(pos - prev)
                prev = pos
    except Exception as e:
        print(f"❌ Error reading {os.path.basename(pcap_path)}: {e}")
        return []

    return packets
