"""
embedder.py

All "text -> vector" code lives here. console.py only calls embed_incident().

Flow when an incident opens (console.py):
    raw logs -> Drain templates (drain_templates.py)
             -> embed text (this file)  -> ONE vector (this file)
             -> saved in incidents.embedding (console.py does the DB write)

One incident = one text = one vector.

The text that gets embedded (no counts, no labels, no service_id):

    error_rate payment
    Timeout connecting to payment-db after <NUM>ms
    Payment failed for user <NUM> txn_<ID>
    Card declined: insufficient funds

Setup:
    pip install sentence-transformers

The first time the model is used, sentence-transformers downloads it
automatically (about 90 MB, one time only) and caches it on your machine.

IMPORTANT: this model gives 384 numbers per vector, so the database column
must be vector(384). If you change EMBED_MODEL_NAME, change EMBED_DIMS and
the column size to match (all-mpnet-base-v2 = 768).
"""

EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EMBED_DIMS = 384
EMBED_TOP_TEMPLATES = 5     # how many templates go into the embed text

_MODEL = None


# ---------------------------------------------------------------------------
# 1. Build the text to embed
# ---------------------------------------------------------------------------

def build_embed_text(service_name, error_type, templates, top_n=EMBED_TOP_TEMPLATES):
    """
    templates: dict {template: count}  (the same dict saved in incidents.log_templates)
    Returns the clean text: header line + the top templates by count.
    Counts are only used to pick the top ones, they are NOT in the text.
    Use service_id as a SQL filter when searching, not inside the vector.
    """
    top = sorted(templates, key=templates.get, reverse=True)[:top_n]
    return f"{error_type} {service_name}\n" + "\n".join(top)


# ---------------------------------------------------------------------------
# 2. Text -> vector
# ---------------------------------------------------------------------------

def get_model():
    """Loads the model once (first use is slow, later calls are instant)."""
    global _MODEL
    if _MODEL is None:
        from sentence_transformers import SentenceTransformer
        print(f"  (loading embedding model {EMBED_MODEL_NAME} ...)")
        _MODEL = SentenceTransformer(EMBED_MODEL_NAME)
    return _MODEL


def embed_text(text):
    """Text -> list of floats. Normalized, so cosine distance (<=>) works well."""
    vec = get_model().encode(text, normalize_embeddings=True)
    vec = [float(x) for x in vec]
    if len(vec) != EMBED_DIMS:
        raise ValueError(
            f"model returned {len(vec)} dims but EMBED_DIMS={EMBED_DIMS}; "
            f"fix EMBED_DIMS and the vector() column size"
        )
    return vec


def to_pgvector(vec):
    """[0.1, 0.2, ...] -> '[0.100000,0.200000,...]' (pgvector text format)."""
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"


# ---------------------------------------------------------------------------
# 3. The one function console.py calls
# ---------------------------------------------------------------------------

def embed_incident(service_name, error_type, templates):
    """
    templates dict -> (embed_text, vector_as_pgvector_string)
    Returns the text too, so the console can print it for debugging.
    """
    text = build_embed_text(service_name, error_type, templates)
    vec = embed_text(text)
    return text, to_pgvector(vec)