# Patch for main.py  (so the AI report shows up in the UI)

Replace `save_report` in main.py with this. It keeps your rule that the LLM never
writes root_cause / resolution / confidence into `incidents`; the full report goes
into a separate `ai_report` column that the UI shows as "AI suggestion".

```python
def save_report(state: InvestigationState) -> dict:
    save_investigation_result(
        state.incident_id,
        symptoms=state.symptoms,
        evidence=state.evidence_summary,
    )
    with get_connection() as cur:
        cur.execute(
            "UPDATE public.incidents SET ai_report = %s WHERE id = %s;",
            (state.report, state.incident_id),
        )
    return {}
```

(`get_connection` is already imported in main.py. api.py creates the column on startup;
if you run the detector first, run `ALTER TABLE public.incidents ADD COLUMN IF NOT EXISTS ai_report text;` once.)
