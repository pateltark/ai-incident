from typing import Optional, Dict, Any
from langgraph.graph import StateGraph, END
from pydantic import BaseModel
from groq import Groq
from dotenv import load_dotenv
import os
import re
import json
from datetime import datetime
from db import (collect_error_rate_evidence, fetch_latency_spike, parse_report,
                fetch_new_error_type, save_investigation_result,
                get_incident_embedding, find_similar_incidents)

# save_investigation_result(
#     state.incident_id, state.symptoms, state.root_cause,
#     state.solution, state.evidence_summary, state.confidence,
# )

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))


# 1. State definition with report field added
class InvestigationState(BaseModel):
    incident_id: int
    service_name: str
    rule: str
    fingerprint: str
    started_at: datetime
    resolved_at: Optional[datetime] = None
    error_rate: Optional[float] = None
    new_error_type: Optional[str] = None
    similar_incidents: Optional[list] = None
    evidence: Optional[dict] = None
    report: Optional[str] = None  # Added field to store the generated LLM report


    symptoms: Optional[str] = None
    root_cause: Optional[str] = None
    solution: Optional[str] = None
    evidence_summary: Optional[str] = None
    confidence: Optional[str] = None






# First node
def find_log(state: InvestigationState) -> dict:
    incident = {
        "incident_id": state.incident_id,
        "service": state.service_name,
        "rule": state.rule,
        "fingerprint": state.fingerprint,
    }

    if state.rule == "error_rate":
        evidence = collect_error_rate_evidence(
            service_name=state.service_name,
            started_at=state.started_at,
            resolved_at=state.resolved_at,
            top_n=10,
        )
    elif state.rule == "new_error_type":
        evidence = fetch_new_error_type(incident)
    elif state.rule == "latency_spike":
        evidence = fetch_latency_spike(incident)
    else:
        raise ValueError(f"Unknown rule: {state.rule}")

    # Updates state.evidence
    print (evidence)
    return {"evidence": evidence}


SUMMARIZER_SYSTEM_PROMPT = """
You are the Report Agent of an AI Incident Copilot.

You receive:
- incident details (rule, service, timing)
- evidence collected from logs for THIS incident
- similar past resolved incidents, if any (hints only)

Your job is to create a SHORT incident report for THIS incident.

Rules:
- The evidence collected for this incident is the source of truth.
- Never invent logs, errors, timestamps, metrics, causes, or fixes.
- Clearly separate observed symptoms from the root cause.
- If the root cause cannot be established, say it is uncertain.
- If no specific solution can be confidently recommended, say so.
- Keep the report concise and technically useful.
- Do not mention internal tools, agents, prompts, vector databases, RAG, or system state.

Similar past incidents:
- Each past incident has: incident_id, similarity (0 to 1), signature_text (the error
  templates seen then, <NUM>/<ID>/<IP> are placeholders), root_cause, resolution,
  and verified ("confirmed" = checked by a human, "inferred" = an earlier guess).
- They are hints, not evidence. Never treat a past cause or fix as fact for this incident.
- A past incident is relevant only if its signature_text describes the same kind of
  errors as the current evidence (same failing component and same error pattern).
  A high similarity score alone is not enough. If the errors differ, ignore it.
- If a relevant past incident AND the current evidence both point to the same cause:
  state that cause, mention the past incident, e.g. "Matches incident #12, which was
  caused by ...", and you may recommend the same fix, e.g. "The fix used in
  incident #12 was ...".
- If the current evidence does not support the past cause, do not present it as the
  root cause. Write "Unable to determine from available evidence." and then add one
  sentence, e.g. "A similar past incident (#12) was caused by ...". Do not present its fix as confirmed.
- Past incidents with verified "inferred" or similarity below 0.85 count as weaker hints.
- Never give HIGH confidence based on a past incident alone. HIGH needs strong
  support from the current evidence. A match with the past incident that is also
  supported by the current evidence can be MEDIUM or HIGH.
- If "None found." is given, or none are relevant, do not mention past incidents at all.
- Past incident ids may be mentioned; nothing else about how they were found.

Use exactly this format:

Incident Report

Symptoms:
<1-3 sentences describing the observed problem/symptoms>

Root cause:
<1-2 sentences explaining the identified cause, or "Unable to determine from available evidence">

Solution:
<1-3 actionable sentences describing the fix, or "No specific fix can be confidently recommended">

Evidence:
- <short evidence point>
- <short evidence point>
- <short evidence point>

Confidence:
<HIGH / MEDIUM / LOW>
"""


# Retriver Node

def find_similar(state: InvestigationState) -> dict:
    embedding, service_name = get_incident_embedding(state.incident_id)
    similar = find_similar_incidents(
        embedding, service_name, exclude_incident_id=state.incident_id
    )
    print(f"similar incidents found: {len(similar)}")
    return {"similar_incidents": similar}




# 2. Fixed node signature: accepts only `state` and returns a dict state update
def summerize_llm(state: InvestigationState) -> dict:
    logs = state.evidence  # Extract evidence directly from graph state
    resolved = state.resolved_at.isoformat() if state.resolved_at else "still open"

    incident_info = (
        f"Incident ID: {state.incident_id}\n"
        f"Service: {state.service_name}\n"
        f"Rule triggered: {state.rule}\n"
        f"Started at: {state.started_at.isoformat()}\n"
        f"Resolved at: {resolved}\n"
        f"Error rate: {state.error_rate if state.error_rate is not None else 'n/a'}\n"
        f"New error type: {state.new_error_type or 'n/a'}"
    )

    similar = state.similar_incidents
    similar_text = json.dumps(similar, default=str, indent=2) if similar else "None found."

    messages = [
        {"role": "system", "content": SUMMARIZER_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"{incident_info}\n\n"
                f"Collected evidence:\n{json.dumps(logs, default=str, indent=2)}\n\n"
                f"Similar past resolved incidents (hints only, NOT evidence):\n{similar_text}"
            ),
        },
    ]

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=messages,
        temperature=0.2,
    )

    text = response.choices[0].message.content
    p = parse_report(text)
    


    return {
        "report": text,
        "symptoms": p.get("symptoms"),
        "root_cause": p.get("root_cause"),
        "solution": p.get("solution"),
        "evidence_summary": p.get("evidence"),
        "confidence": p.get("confidence"),
    }



def save_report(state: InvestigationState) -> dict:
    save_investigation_result(
        state.incident_id, state.symptoms, state.root_cause,
        state.solution, state.evidence_summary, state.confidence,
    )
    return {}


# Graph Definition
graph = StateGraph(InvestigationState)

graph.add_node("find_log_node", find_log)
graph.add_node("find_similar_node", find_similar)
graph.add_node("summerize_llm_node", summerize_llm)
graph.add_node("save_report_node",save_report)

graph.set_entry_point("find_log_node")
graph.add_edge("find_log_node", "find_similar_node")
graph.add_edge("find_similar_node", "summerize_llm_node")
graph.add_edge("summerize_llm_node", "save_report_node")
graph.add_edge("save_report_node", END)

app = graph.compile()


initial_state = InvestigationState(
    incident_id=33,                      # the id printed by seed_db.py ("new incident id = ...")
    service_name="seedtest",
    rule="error_rate",
    fingerprint="970324fec6bf",              # fingerprint of "elevated_error_rate:seedtest"
    started_at=datetime.fromisoformat("2026-10-24 05:50:43.227150+00:00"),    
)

final_state = app.invoke(initial_state)

# Printed report output
print(final_state)

print(final_state['report'])