from dotenv import load_dotenv
from groq import Groq
import os
from tools import QUERY_LOGS_TOOL, query_logs_tool
import json


load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

tools = [QUERY_LOGS_TOOL]

SYSTEM_PROMPT = """
You are an AI Incident Copilot.

Your job is to help investigate software incidents using
application logs and incident data available through your tools.

Rules:

1. Understand the user's incident investigation question.

2. Use the available tools when you need information from
   application logs or other operational data.

3. Do not invent logs, errors, timestamps, services,
   incidents, causes, or metrics.

4. Base your answer only on:
   - Information provided by the user
   - Information returned by the tools

5. If the available data is insufficient to determine the cause,
   clearly say that the cause cannot be determined from the
   available data.

6. When analyzing errors, identify:
   - Affected service
   - Error messages
   - Relevant timestamps
   - Latency information when available
   - Patterns or repeated errors

7. Clearly distinguish between:
   - What the data directly shows
   - What is a possible explanation

8. Do not claim a root cause unless the available data supports it.

9. Keep responses concise and useful for an engineer
   investigating an incident.

10. When useful, suggest what additional information should
    be investigated next.
"""




user_question = input("Ask about an incident: ")

messages = [
    {
        "role": "system",
        "content": SYSTEM_PROMPT
    },
    {
        "role": "user",
        "content": user_question
    }
]


response = client.chat.completions.create(
    model="openai/gpt-oss-20b",
    messages=messages,
    tools=tools,
    tool_choice="auto"
)

assistant_message = response.choices[0].message


if assistant_message.tool_calls:

    # Add the assistant's tool-call message
    messages.append(assistant_message)

    for tool_call in assistant_message.tool_calls:

        tool_name = tool_call.function.name

        arguments = json.loads(
            tool_call.function.arguments
        )

        print("\nLLM requested tool:")
        print(tool_name)
        print("Arguments:", arguments)

        # --------------------------------------------------
        # EXECUTE THE ACTUAL PYTHON FUNCTION
        # --------------------------------------------------

        if tool_name == "query_logs":

            tool_result = query_logs_tool(
                service_name=arguments.get("service_name"),
                level=arguments.get("level"),
                start_time=arguments.get("start_time"),
                end_time=arguments.get("end_time")
            )

        else:
            tool_result = {
                "error": f"Unknown tool: {tool_name}"
            }


        # --------------------------------------------------
        # SEND TOOL OUTPUT BACK TO LLM
        # --------------------------------------------------

        messages.append(
            {
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(
                    tool_result,
                    default=str
                )
            }
        )


    # --------------------------------------------------
    # SECOND LLM CALL
    # --------------------------------------------------

    final_response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=messages,
        tools=tools,
        tool_choice="auto"
    )


    print("\nAI Incident Copilot:")
    print(
        final_response.choices[0].message.content
    )


else:

    # LLM answered without using a tool
    print("\nAI Incident Copilot:")
    print(assistant_message.content)
