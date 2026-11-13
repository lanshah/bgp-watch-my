import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bgpwatch import synthetic  # noqa: E402
from bgpwatch.config import load_config  # noqa: E402
from bgpwatch.rpki import RpkiValidator, Vrp  # noqa: E402
from bgpwatch.state import RouteState  # noqa: E402
from bgpwatch.detectors import Detectors  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def cfg():
    return load_config()


@pytest.fixture
def syn_state():
    return RouteState(synthetic.watchlist(), synthetic.baseline())


@pytest.fixture
def syn_rpki():
    return RpkiValidator([Vrp(v["asn"], v["prefix"], v["maxLength"], v["ta"]) for v in synthetic.VRPS])


@pytest.fixture
def syn_det(syn_state, syn_rpki, cfg):
    return Detectors(syn_state, syn_rpki, cfg.detect)


def ris(ts, peer_i, prefix=None, path=None, withdraw=None, host=None):
    """Build a RIS Live envelope from a synthetic peer."""
    p = synthetic.PEERS[peer_i]
    d = {"timestamp": ts, "peer": p["ip"], "peer_asn": str(p["asn"]), "id": f"t-{ts}-{peer_i}",
         "host": host or p["host"], "type": "UPDATE"}
    if withdraw:
        d.update({"withdrawals": [withdraw], "announcements": []})
    else:
        d.update({"path": path, "announcements": [{"next_hop": p["ip"], "prefixes": [prefix]}], "withdrawals": []})
    return {"type": "ris_message", "data": d}
