import sys
from pathlib import Path
import importlib
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def import_pcap_utils():
    modules = {}
    scapy_all = types.ModuleType('scapy.all')
    scapy_all.RawPcapReader = lambda *a, **k: iter([])
    scapy_all.RadioTap = lambda *a, **k: None
    scapy = types.ModuleType('scapy')
    scapy.all = scapy_all
    modules['scapy'] = scapy
    modules['scapy.all'] = scapy_all
    for name, mod in modules.items():
        sys.modules[name] = mod
    return importlib.reload(importlib.import_module('pcap_utils'))


def test_load_pcap_fast_nonexistent(tmp_path):
    pu = import_pcap_utils()
    result = pu.load_pcap_fast(str(tmp_path / 'missing.pcap'))
    assert result == []
