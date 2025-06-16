import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import importlib
import os
import types

# Helper to import analyze_evidence with stubbed dependencies

def import_analyze_evidence():
    modules = {}

    openai = types.ModuleType('openai')
    openai.OpenAI = lambda api_key=None: None
    modules['openai'] = openai

    anthropic = types.ModuleType('anthropic')
    anthropic.Anthropic = lambda api_key=None: None
    modules['anthropic'] = anthropic

    dotenv = types.ModuleType('dotenv')
    dotenv.load_dotenv = lambda: None
    modules['dotenv'] = dotenv

    pick = types.ModuleType('pick')
    pick.pick = lambda *args, **kwargs: ('', 0)
    modules['pick'] = pick

    scapy_all = types.ModuleType('scapy.all')
    for name in ['Dot11', 'Dot11Deauth', 'Dot11Disas', 'Dot11Auth', 'Dot11ProbeReq', 'RadioTap']:
        setattr(scapy_all, name, type(name, (), {}))
    scapy_all.rdpcap = lambda *args, **kwargs: []
    scapy_all.RawPcapReader = lambda *a, **k: iter([])
    class DummyPcapReader:
        def __init__(self, *a, **k):
            pass

        def __iter__(self):
            return iter([])

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

    scapy_all.PcapReader = DummyPcapReader
    scapy = types.ModuleType('scapy')
    scapy.all = scapy_all
    modules['scapy'] = scapy
    modules['scapy.all'] = scapy_all

    for name, mod in modules.items():
        sys.modules[name] = mod

    return importlib.reload(importlib.import_module('analyze_evidence'))


def test_format_prompt_for_ai_basic(tmp_path):
    ae = import_analyze_evidence()
    summary = {'aa:bb': {'packet_types': {'ARP Spoofing': 2, 'Rogue AP': 1}}}
    prompt = ae.format_prompt_for_ai(summary)
    assert prompt.startswith('You are a cybersecurity expert')
    assert '- ARP Spoofing' in prompt
    assert '- Rogue AP' in prompt


def test_load_known_networks_from_scanner():
    ae = import_analyze_evidence()
    nets = ae.load_known_networks_from_scanner('scan.py')
    assert isinstance(nets, dict)
    assert nets.get('Goliath_5G') == '00:31:92:1b:79:55'


def test_save_ai_report_creates_file(tmp_path):
    ae = import_analyze_evidence()
    ae.AI_REPORTS_DIRECTORY = str(tmp_path)
    ae.save_ai_report('hello world')
    files = list(tmp_path.glob('ai_report_*.txt'))
    assert len(files) == 1
    with open(files[0], 'r') as f:
        content = f.read()
    assert content == 'hello world'
