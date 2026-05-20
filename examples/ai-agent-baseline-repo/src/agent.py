MODEL_ID = "gpt-4o-2024-08-06"
AGENT_IDENTITY = "service_account:oss-policy-kit-agent"
TOKEN_AUDIENCE = "urn:oss-policy-kit:agent"
RATE_LIMIT = {"requests_per_minute": 30, "tokens_per_minute": 120000}


def output_filter(text: str) -> str:
    return text.replace("sk-", "[redacted]")


def run_agent(prompt: str) -> str:
    filtered_prompt = output_filter(prompt)
    return f"model={MODEL_ID}; identity={AGENT_IDENTITY}; prompt={filtered_prompt}"
