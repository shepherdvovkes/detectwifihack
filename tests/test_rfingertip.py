import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import importlib
import types


# Helper to import rfingertip with stubbed dependencies

def import_rfingertip():
    modules = {}

    # Stub PyQt6 modules
    qtcore = types.ModuleType('PyQt6.QtCore')
    qtcore.QObject = object
    qtcore.QThread = object
    qtcore.pyqtSignal = lambda *args, **kwargs: None
    qtwidgets = types.ModuleType('PyQt6.QtWidgets')
    for name in ['QApplication', 'QWidget', 'QVBoxLayout', 'QPushButton',
                 'QFileDialog', 'QLabel', 'QMessageBox']:
        setattr(qtwidgets, name, object)
    modules['PyQt6'] = types.ModuleType('PyQt6')
    modules['PyQt6.QtCore'] = qtcore
    modules['PyQt6.QtWidgets'] = qtwidgets

    # Stub matplotlib
    matplotlib = types.ModuleType('matplotlib')
    pyplot = types.ModuleType('matplotlib.pyplot')
    pyplot.subplots = lambda *a, **k: (object(), [object(), object(), object()])
    pyplot.show = lambda *a, **k: None
    modules['matplotlib'] = matplotlib
    modules['matplotlib.pyplot'] = pyplot

    # Stub scapy
    scapy_all = types.ModuleType('scapy.all')
    scapy_all.rdpcap = lambda *a, **k: []
    scapy_all.RawPcapReader = lambda *a, **k: iter([])
    scapy_all.PcapReader = lambda *a, **k: iter([])
    for name in ['RadioTap', 'Dot11']:
        setattr(scapy_all, name, type(name, (), {}))
    scapy = types.ModuleType('scapy')
    scapy.all = scapy_all
    modules['scapy'] = scapy
    modules['scapy.all'] = scapy_all

    for name, mod in modules.items():
        sys.modules[name] = mod

    return importlib.reload(importlib.import_module('rfingertip'))


def test_detect_similar_fingerprints():
    rf = import_rfingertip()
    fps = [
        {'mac': 'a', 'rssi_std': 1.0, 'iat_std': 0.01},
        {'mac': 'b', 'rssi_std': 1.1, 'iat_std': 0.02},
        {'mac': 'c', 'rssi_std': 3.0, 'iat_std': 0.5},
    ]
    clusters = rf.detect_similar_fingerprints(fps)
    assert len(clusters) == 1
    assert {fp['mac'] for fp in clusters[0]} == {'a', 'b'}
