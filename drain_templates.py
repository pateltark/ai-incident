"""
drain_templates.py

All Drain3 code lives here. console.py only calls cluster_logs().

What it does:
    raw log messages  ->  Drain3 clusters  ->  Counter({template: count})

    "Payment failed for user 8841 txn_8f3a9c01d2"   ┐
    "Payment failed for user 1203 txn_77ab12cd90"   ├─> "Payment failed for user <NUM> txn_<ID>"  (x2)
    "Timeout connecting to payment-db after 5003ms" ──> "Timeout connecting to payment-db after <NUM>ms"  (x1)

The raw logs are NOT changed or deleted. They stay in application_logs.

Setup:
    pip install drain3

No drain3.ini needed: the settings and the masking regexes are below.
"""

from collections import Counter

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

DRAIN_SIM_TH = 0.5        # higher = stricter (more templates), lower = more merging
DRAIN_DEPTH = 4           # parse-tree depth, 4 is fine
DRAIN_MAX_CHILDREN = 100
DRAIN_MAX_CLUSTERS = 1000 # memory cap per service

# Known variable parts are masked BEFORE Drain sees the line. Drain then only
# has to find the unknown variable parts, which it turns into <*>.
# Order matters: timestamps/uuids/ips first, plain numbers last.
# Look-arounds (not \b) so ids glued to '_' or '=' still match (txn_8f3a..., id=a81f...).
_MASKING_RULES = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "TS"),
    (r"(?<![0-9A-Za-z])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Za-z])", "ID"),
    (r"(?<![0-9A-Za-z])(?:\d{1,3}\.){3}\d{1,3}(?![0-9A-Za-z])", "IP"),
    (r"(?<![0-9A-Za-z])(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{8,}(?![0-9A-Za-z])", "ID"),
    (r"(?<![A-Za-z])\d+(?:\.\d+)?", "NUM"),   # 'p95' and 'db2' stay, '5003ms' -> '<NUM>ms'
]

# ---------------------------------------------------------------------------
# One miner per service, kept in memory
# ---------------------------------------------------------------------------

_MINERS = {}


def _make_config():
    cfg = TemplateMinerConfig()
    cfg.drain_sim_th = DRAIN_SIM_TH
    cfg.drain_depth = DRAIN_DEPTH
    cfg.drain_max_children = DRAIN_MAX_CHILDREN
    cfg.drain_max_clusters = DRAIN_MAX_CLUSTERS
    cfg.profiling_enabled = False
    cfg.masking_instructions = [MaskingInstruction(rx, name) for rx, name in _MASKING_RULES]
    return cfg


def get_miner(service_name):
    """One miner per service, so templates of 'payment' never mix with 'auth'."""
    if service_name not in _MINERS:
        _MINERS[service_name] = TemplateMiner(config=_make_config())
    return _MINERS[service_name]


def reset_miner(service_name=None):
    """Forget what a miner learned (one service, or all of them)."""
    if service_name is None:
        _MINERS.clear()
    else:
        _MINERS.pop(service_name, None)


# ---------------------------------------------------------------------------
# Main function: raw messages -> {template: count}
# ---------------------------------------------------------------------------

def cluster_logs(service_name, messages):
    """
    messages: list of raw log message strings (e.g. the incident window).
    Returns a Counter({template: how many of these messages matched it}).

    Two passes, because the first log of a new cluster comes back as raw text
    and only becomes '<*>' when similar logs arrive later:
      1. learn : feed every message to Drain (builds / updates the templates)
      2. count : look every message up again against the FINAL templates
    """
    miner = get_miner(service_name)

    for msg in messages:                       # pass 1: learn
        miner.add_log_message(msg)

    counts = Counter()
    for msg in messages:                       # pass 2: count with final templates
        cluster = miner.match(msg, full_search_strategy="fallback")
        if cluster is not None:
            counts[cluster.get_template()] += 1
        else:
            counts[miner.masker.mask(msg)] += 1   # safety net, should be rare
    return counts


def show_clusters(service_name):
    """For the console 'templates' command: [(cluster_id, total_size, template), ...]"""
    miner = get_miner(service_name)
    clusters = sorted(miner.drain.clusters, key=lambda c: c.size, reverse=True)
    return [(c.cluster_id, c.size, c.get_template()) for c in clusters]