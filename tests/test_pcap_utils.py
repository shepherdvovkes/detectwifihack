import sys
from pathlib import Path
import importlib
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def import_pcap_utils():
    modules = {}
    sys.modules.pop('dpkt', None)

    class DummyRawReader:
        def __init__(self, *a, **k):
            self.pkts = [b'c', b'd']
            self.offset = 0
            self.f = types.SimpleNamespace(tell=lambda: 0)

        def __iter__(self):
            for p in self.pkts:
                yield p, None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

    scapy_all = types.ModuleType('scapy.all')
    scapy_all.RawPcapReader = DummyRawReader
    scapy_all.RadioTap = lambda buf: ('RT', buf)
    scapy = types.ModuleType('scapy')
    scapy.all = scapy_all
    modules['scapy'] = scapy
    modules['scapy.all'] = scapy_all

    for name, mod in modules.items():
        sys.modules[name] = mod
    return importlib.reload(importlib.import_module('pcap_utils'))


def import_pcap_utils_with_dpkt():
    modules = {}

    scapy_all = types.ModuleType('scapy.all')
    scapy_all.RawPcapReader = lambda *a, **k: iter([])
    scapy_all.RadioTap = lambda buf: ('RT', buf)
    scapy = types.ModuleType('scapy')
    scapy.all = scapy_all
    modules['scapy'] = scapy
    modules['scapy.all'] = scapy_all

    dpkt = types.ModuleType('dpkt')

    class DummyReader:
        def __init__(self, f):
            pass

        def __iter__(self):
            return iter([(0, b'a'), (1, b'b')])

    dpkt.pcap = types.SimpleNamespace(Reader=DummyReader)
    modules['dpkt'] = dpkt

    for name, mod in modules.items():
        sys.modules[name] = mod
    return importlib.reload(importlib.import_module('pcap_utils'))


def test_load_pcap_fast_nonexistent(tmp_path):
    pu = import_pcap_utils()
    result = pu.load_pcap_fast(str(tmp_path / 'missing.pcap'))
    assert result == []


def test_load_pcap_fast_with_dpkt(tmp_path):
    p = tmp_path / "file.pcap"
    p.write_bytes(b"data")
    pu = import_pcap_utils_with_dpkt()
    result = pu.load_pcap_fast(str(p))
    assert result == [('RT', b'a'), ('RT', b'b')]


def test_load_pcap_fast_fallback(tmp_path):
    p = tmp_path / "file2.pcap"
    p.write_bytes(b"data")
    pu = import_pcap_utils()
    result = pu.load_pcap_fast(str(p))
    assert result == [('RT', b'c'), ('RT', b'd')]
