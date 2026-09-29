from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from tools import TOOLS, query_logs_tool, find_incident_tool, query_slow_requests_tool
from groq import Groq
from dotenv import load_dotenv
import os
import json

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))


class InvestigationState(TypedDict):
   
    alert: dict 
    logs: List[Dict[str, Any]]
    incidents: List[Dict[str, Any]]
    slow_requests: List[Dict[str, Any]]
    analysis: str | None


class Alert(BaseModel):
    incident_id: int
    service: str
    rule: str                 
    fingerprint: str
    error_rate: Optional[float] = None



tools = [
    query_logs_tool,
    find_incident_tool,
    query_slow_requests_tool,
]


SUMMARIZER_SYSTEM_PROMPT = """
You are the Summarizer / Report Agent of an AI Incident Copilot.

Your job is to analyze all available investigation evidence and produce
a structured incident report.

You will receive:

1. The original user question.
2. The investigation plan created by the Planner.
3. Current investigation results collected by the Analyst.
4. Similar historical incidents retrieved by the Retriever.

Your responsibilities:

1. Analyze the current investigation results first.
   The current database/tool results are the primary source of truth.

2. Explain what is currently happening based on the evidence.

3. Identify the most likely root cause when the evidence supports one.

4. Use similar historical incidents as supporting context, not as proof.
   A historical incident must never be treated as the current root cause
   unless the current evidence supports the connection.

5. Suggest a practical fix based on the available evidence.

6. Assign a confidence level:
   - HIGH: Current evidence directly supports the conclusion.
   - MEDIUM: Evidence supports the conclusion, but some uncertainty remains.
   - LOW: The conclusion is mainly based on historical similarity or weak evidence.

7. Clearly distinguish:
   - Observed facts
   - Likely root cause
   - Historical similarity
   - Suggested fix
   - Uncertainty

8. Never invent:
   - logs
   - incidents
   - timestamps
   - errors
   - metrics
   - root causes
   - fixes
   - database results

9. If the available evidence is insufficient to determine the root cause,
   explicitly state that the root cause is uncertain.

10. If no similar historical incidents were found, do not treat that as
    evidence that the incident is unique.

11. Do not mention internal implementation details such as LangGraph,
    tools, agents, prompts, or state unless explicitly asked.

Return the result using this structure:

Incident Report

What happened:
<brief description of the observed problem>

Evidence:
- <important evidence from current investigation>

Likely root cause:
<most likely explanation supported by the evidence>
or
<Unable to determine from available evidence>

Suggested fix:
<practical action supported by the evidence>
or
<No specific fix can be confidently recommended>

Historical similarity:
<relevant similar incidents and what they suggest>
or
<No relevant historical incidents found>

Confidence:
<HIGH / MEDIUM / LOW>

Reasoning:
<brief explanation of why the root cause and confidence level
were selected>

Remember:
Current investigation evidence has higher priority than historical
incident similarity.
"""



ANALYST_SYSTEM_PROMPT = """
You are the Analyst agent of an AI Incident Copilot.

Your job is to investigate the user's incident question by using the
available read-only investigation tools and return the evidence collected
from those tools.

Your responsibilities:

1. Understand the user's investigation request or investigation plan.

2. Determine which available tool is relevant to the request.

3. Use the appropriate tools to retrieve the required data.

Available tools include:
- query_logs_tool
- find_incident_tool
- query_slow_requests_tool

4. Choose tool arguments based only on information available in the
   user's request or investigation plan.

5. If multiple types of information are required, call all relevant
   tools.

6. Do not invent tool arguments, database results, logs, incidents,
   timestamps, services, errors, or latency values.

7. If a tool returns an error, inspect the error and retry the
   investigation once with corrected arguments when possible.

8. Do not retry the same failed tool call more than once.

9. If a tool returns no matching records, preserve that result and
   report that no matching data was found.

10. Only perform read-only investigation. Never modify, delete, or
    insert database data.

11. Do not diagnose the root cause. Your job is to collect evidence,
    not make the final incident diagnosis.

12. Continue investigating until all relevant parts of the request
    have been investigated.

13. Return the collected tool results in a structured form that can
    be passed to another LLM for final analysis.

The database/tool results are the source of truth.
"""


def analyst_llm(state: IncidentState) -> Dict[str, Any]:

    messages = [
        {
            "role": "system",
            "content": ANALYST_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": state["user_question"]
        }
    ]

    response = client.chat.completions.create(
    model="openai/gpt-oss-20b",
    messages=messages,
    tools=TOOLS,
    tool_choice="auto",
)
    msg = response.choices[0].message

    logs, incidents, slow = [], [], []

    for call in msg.tool_calls or []:
        name = call.function.name
        try:
            args = json.loads(call.function.arguments)
        except json.JSONDecodeError:
            args = {}

        try:
            if name == "query_logs_tool":
                logs.append(query_logs_tool(**args))
            elif name == "find_incident_tool":
                incidents.append(find_incident_tool(**args))
            elif name == "query_slow_requests_tool":
                slow.append(query_slow_requests_tool(**args))
        except Exception as e:
            err = {"error": str(e), "tool": name, "args": args}
            # store the error so the summarizer can see it
            (logs if name == "query_logs_tool"
            else incidents if name == "find_incident_tool"
            else slow).append(err)

    return {"logs": logs, "incidents": incidents, "slow_requests": slow}



def summerize_llm (state: IncidentState) -> Dict[str, Any]:
    # Correct key name access ('incidents' instead of 'incident')
    logs = state.get("logs", [])
    incidents = state.get("incidents", [])
    latency = state.get("high_latency", [])

    context = f"Incidents: {incidents}\nLogs: {logs}\nLatency {latency}"

    messages = [
        {"role": "system", "content": SUMMARIZER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Question: {state['user_question']}\n{context}"}
    ]

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=messages,
    )

    # Return dictionary update instead of direct mutation
    return {
        "analysis": response.choices[0].message.content
    }


# Graph Definition
graph = StateGraph(IncidentState)

graph.add_node("planner_node", analyst_llm)
graph.add_node("llm_analyst_node", summerize_llm)

graph.set_entry_point("planner_node")
graph.add_edge("planner_node", "llm_analyst_node")
graph.add_edge("llm_analyst_node", END)

app = graph.compile()



def handle_incident_opened_event(alert_data: Dict[str, Any]):
    """Automatically triggered in-memory when an incident opens."""
    print(f"\n[Agent Triggered] Investigating new incident ID {alert_data['incident_id']} on service '{alert_data['service_name']}'...")
    
    # Construct state directly from the event
    initial_state: IncidentState = {
        "user_question": f"Investigate active incident #{alert_data['incident_id']} for service '{alert_data['service_name']}'. Rule triggered: {alert_data['rule']}. Description: {alert_data['description']}",
        "service_name": alert_data["service_name"],
        "alert": alert_data,
        "logs": [],
        "incidents": [],
        "slow_requests": [],
        "analysis": None
    }

    # Execute LangGraph investigation automatically
    final_state = app.invoke(initial_state)
    print("\n--- [AUTOMATED AGENT REPORT] ---")
    print(final_state.get("analysis"))
    print("----------------------------------\n")


initial_state: IncidentState = {
    "user_question": "What is the error in payment service ?",
    "service_name": None,  # Corrected from [] to None
    "logs": [],
    "incidents": [],
    "slow_requests": [],
    "analysis": None
}

final_state = app.invoke(initial_state)

print("\nAnalysis:\n", final_state.get("analysis"))