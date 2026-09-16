from dotenv import load_dotenv
from groq import Groq
import os

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

SYSTEM_PROMPT = """
You are an AI Incident Copilot.

You help users understand software incidents from application logs.

Rules:
- Use only the log data provided to you.
- Do not invent facts, errors, timestamps, services, or causes.
- If the provided data does not contain enough information, say so.
- Give a concise and clear explanation.
"""

QUERIES = {
    "recent_errors": [
        {
            "service": "payment",
            "level": "ERROR",
            "message": "Database connection failed"
        },
        {
            "service": "checkout",
            "level": "ERROR",
            "message": "Payment gateway timeout"
        }
    ],

    "payment_errors": [
        {
            "service": "payment",
            "level": "ERROR",
            "message": "Database connection failed"
        }
    ],

    "checkout_errors": [
        {
            "service": "checkout",
            "level": "ERROR",
            "message": "Payment gateway timeout"
        }
    ]
}


def find_error (query_name):

    return QUERIES.get(quer_name, [])


query_name = "payment_errors"

result = QUERIES.get(query_name, [])


# -------------------------
# Send result to LLM
# -------------------------

user_prompt = f"""
User asked about an incident.

Here is the relevant log data:

{result}

Explain what happened based on these logs.
"""

response = client.chat.completions.create(
    model="openai/gpt-oss-20b",
    messages=[
        {
            "role": "system",
            "content": SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": user_prompt
        }
    ]
)

print(response.choices[0].message.content)