# drain_templates.py
from collections import Counter
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

_MINERS = {}   # one miner per service, so templates stay stable per service


def get_miner(service_name: str) -> TemplateMiner:
    if service_name not in _MINERS:
        cfg = TemplateMinerConfig()
        cfg.load("drain3.ini")
        cfg.profiling_enabled = False
        _MINERS[service_name] = TemplateMiner(config=cfg)
    return _MINERS[service_name]


def cluster_logs(service_name: str, messages: list[str]) -> Counter:
    """Raw log messages -> Counter({template: count})."""
    miner = get_miner(service_name)

    for msg in messages:                     # pass 1: learn templates
        miner.add_log_message(msg)

    counts = Counter()
    for msg in messages:                     # pass 2: count with final templates
        cluster = miner.match(msg, full_search_strategy="fallback")
        if cluster is not None:
            counts[cluster.get_template()] += 1
    return counts


def build_embed_text(service_name: str, rule: str, counts: Counter, top_n: int = 5) -> str:
    """Clean text to embed: no counts, no labels, only top templates."""
    top = [t for t, _ in counts.most_common(top_n)]
    return f"{rule} {service_name}\n" + "\n".join(top)