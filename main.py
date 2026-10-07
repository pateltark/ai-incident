from typing import Optional, Dict, Any
from langgraph.graph import StateGraph, END
from pydantic import BaseModel
from groq import Groq
from dotenv import load_dotenv
import os
import json
from datetime import datetime
from db import collect_error_rate_evidence, fetch_latency_spike, fetch_new_error_type, parse_report, save_investigation_result


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
    evidence: Optional[dict] = None
    report: Optional[str] = None  # Added field to store the generated LLM report


    symptoms: Optional[str] = None
    root_cause: Optional[str] = None
    solution: Optional[str] = None
    evidence_summary: Optional[str] = None
    confidence: Optional[str] = None



def save_report(state: InvestigationState) -> dict:
    save_investigation_result(
        state.incident_id, state.symptoms, state.root_cause,
        state.solution, state.evidence_summary, state.confidence,
    )
    return {}


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
- evidence collected from logs
- investigation findings, if available

Your job is to create a SHORT incident report based ONLY on the provided evidence and findings.

Rules:
- The provided evidence is the source of truth.
- Never invent logs, errors, timestamps, metrics, causes, or fixes.
- Clearly separate observed symptoms from the root cause.
- If the root cause cannot be established, say it is uncertain.
- If no specific solution can be confidently recommended, say so.
- Keep the report concise and technically useful.
- Do not mention internal tools, agents, prompts, vector databases, RAG, or system state.

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

    messages = [
        {"role": "system", "content": SUMMARIZER_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"{incident_info}\n\nCollected evidence:\n{json.dumps(logs, default=str, indent=2)}",
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
    "symptoms": p["symptoms"],
    "root_cause": p["root_cause"],
    "solution": p["solution"],
    "evidence_summary": p["evidence"],
    "confidence": p["confidence"],
    }




# Graph Definition
graph = StateGraph(InvestigationState)

graph.add_node("find_log_node", find_log)
graph.add_node("summerize_llm_node", summerize_llm)

graph.set_entry_point("find_log_node")
graph.add_edge("find_log_node", "summerize_llm_node")
graph.add_edge("summerize_llm_node", END)

app = graph.compile()


initial_state = InvestigationState(
    incident_id=14,
    service_name="payment",
    rule="error_rate",
    fingerprint="206505175d85",
    started_at=datetime.fromisoformat("2026-10-07 11:46:20.987586"),
)

final_state = app.invoke(initial_state)

# Printed report output
print(final_state["report"])



# def handle_incident_opened_event(alert_data: Dict[str, Any]):
#     """Automatically triggered in-memory when an incident opens."""
#     print(f"\n[Agent Triggered] Investigating new incident ID {alert_data['incident_id']} on service '{alert_data['service_name']}'...")
    
#     # Construct state directly from the event
#     initial_state: InvestigationState = {
#         "user_question": f"Investigate active incident #{alert_data['incident_id']} for service '{alert_data['service_name']}'. Rule triggered: {alert_data['rule']}. Description: {alert_data['description']}",
#         "service_name": alert_data["service_name"],
#         "alert": alert_data,
#         "logs": [],
#         "incidents": [],
#         "slow_requests": [],
#         "analysis": None
#     }

#     # Execute LangGraph investigation automatically
#     final_state = app.invoke(initial_state)
#     print("\n--- [AUTOMATED AGENT REPORT] ---")
#     print(final_state.get("analysis"))
#     print("----------------------------------\n")


# initial_state: InvestigationState = {
#     "user_question": "What is the error in payment service ?",
#     "service_name": None,  # Corrected from [] to None
#     "logs": [],
#     "incidents": [],
#     "slow_requests": [],
#     "analysis": None
# }

# final_state = app.invoke(initial_state)

# print("\nAnalysis:\n", final_state.get("analysis"))