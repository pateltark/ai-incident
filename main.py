from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, END
from tools import TOOL, query_logs_tool, find_incident_tool
from groq import Groq
from dotenv import load_dotenv
import os
import json

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))


class IncidentState(TypedDict):
    user_question: str
    service_name: str | None
    logs: List[Dict[str, Any]]
    incidents: List[Dict[str, Any]]
    slow_requests: List[Dict[str, Any]]
    analysis: str | None


SYSTEM_PROMPT = """
You are an AI Incident Copilot.

Your job is to help engineers investigate software incidents.

Rules:
1. Understand the user's incident investigation question.
2. When the user asks about an incident for a specific service,
   use the available incident tool to retrieve the relevant incident data.
3. Use the tool arguments appropriately:
   - service_name: identify the service being investigated.
   - status: use only when the user specifies or clearly asks for a status.
   - severity: use only when the user specifies or clearly asks for a severity.
4. Do not invent incident information.
5. Base your answer only on:
   - Information provided by the user.
   - Information returned by the available tools.
6. Clearly report relevant information such as:
   - Service
   - Incident title
   - Description
   - Severity
   - Status
   - Start time
   - Resolution time, if available
7. If no matching incident is found, clearly say that no matching incident
   was found in the available data.
8. Do not claim a root cause unless the available data supports it.
9. Keep the response concise and useful for an engineer investigating
   an incident.
"""


def planner(state: IncidentState) -> Dict[str, Any]:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": state["user_question"]}
    ]

    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=messages,
        tools=TOOL,
        tool_choice="auto"
    )

    assistant_message = response.choices[0].message

    logs_results = []
    incidents_results = []

    if assistant_message.tool_calls:
        for tool_call in assistant_message.tool_calls:
            tool_name = tool_call.function.name
            
            try:
                arguments = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                arguments = {}

            print(f"\nLLM requested tool: {tool_name}")
            print("Arguments:", arguments)

            if tool_name == "query_logs_tool":
                res = query_logs_tool(**arguments)
                print("Tool output (logs):", res)
                if isinstance(res, list):
                    logs_results.extend(res)
                elif res:
                    logs_results.append(res)

            elif tool_name == "find_incident_tool":
                res = find_incident_tool(**arguments)
                print("Tool output (incidents):", res)
                if isinstance(res, list):
                    incidents_results.extend(res)
                elif res:
                    incidents_results.append(res)

    # Return state updates for LangGraph to merge automatically
    return {
        "logs": logs_results,
        "incidents": incidents_results
    }


ANALYST_SYSTEM_PROMPT = """
You are an AI Incident Copilot analyst.
Summarize the incident/log data below for the engineer.
Only use the data given. If there is no data, say so.
Keep it short and clear.
"""


def llm_analyst(state: IncidentState) -> Dict[str, Any]:
    # Correct key name access ('incidents' instead of 'incident')
    logs = state.get("logs", [])
    incidents = state.get("incidents", [])

    context = f"Incidents: {incidents}\nLogs: {logs}"

    messages = [
        {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
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

graph.add_node("planner_node", planner)
graph.add_node("llm_analyst_node", llm_analyst)

graph.set_entry_point("planner_node")
graph.add_edge("planner_node", "llm_analyst_node")
graph.add_edge("llm_analyst_node", END)

app = graph.compile()


# Execution Entry Point
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