import os

try:
    from scapy.all import RawPcapReader, RadioTap
except Exception:  # scapy may be stubbed in tests
    RawPcapReader = None
    RadioTap = None

def load_pcap_fast(pcap_path):
    """Efficiently load packets from a PCAP using dpkt if available."""
    try:
        file_size = os.path.getsize(pcap_path)
    except FileNotFoundError:
        print(f"❌ File not found: {pcap_path}")
        return []
    packets = []


    if RawPcapReader is None or RadioTap is None:
        return packets

    # Try the dpkt reader first for speed
    try:
        import dpkt  # type: ignore
        with open(pcap_path, "rb") as f:
            for ts, buf in dpkt.pcap.Reader(f):
                try:
                    pkt = RadioTap(buf)
                except Exception:
                    continue
                packets.append(pkt)
        return packets
    except Exception:
        packets = []  # fall back to RawPcapReader

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


def load_pcap_in_chunks(pcap_path, chunk_count=10):
    """Load a PCAP file in roughly ``chunk_count`` pieces and return all packets.

    This is a memory-friendly alternative that reads the file sequentially and
    combines the packets from each chunk. If the file cannot be read, an empty
    list is returned.
    """
    try:
        file_size = os.path.getsize(pcap_path)
    except FileNotFoundError:
        print(f"❌ File not found: {pcap_path}")
        return []

    if RawPcapReader is None or RadioTap is None:
        return []

    chunk_size = max(1, file_size // max(1, chunk_count))
    packets = []

    try:
        with RawPcapReader(pcap_path) as reader:
            bytes_read = 0
            for pkt_data, _ in reader:
                try:
                    pkt = RadioTap(pkt_data)
                except Exception:
                    continue
                packets.append(pkt)
                bytes_read += len(pkt_data)
                if bytes_read >= chunk_size:
                    bytes_read = 0
    except Exception as e:
        print(f"❌ Error reading {os.path.basename(pcap_path)}: {e}")
        return []

    return packets
