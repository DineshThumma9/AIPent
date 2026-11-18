#!/usr/bin/env python3
"""Ping every configured LLM provider with "ping" and report whether it answers "pong".

Run from anywhere: backend/.venv/bin/python backend/scripts/ping_keys.py
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

PROMPT = "ping"


def openrouter(key):
    from langchain_openrouter import ChatOpenRouter

    return ChatOpenRouter(
        model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
        api_key=key,
        temperature=0,
        timeout=15,
        max_retries=0,
        max_tokens=16,
    )


def gemini(key):
    from langchain_google_genai import ChatGoogleGenerativeAI

    return ChatGoogleGenerativeAI(
        model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
        google_api_key=key,
        temperature=0,
        timeout=15,
        max_retries=0,
        max_output_tokens=16,
    )


def groq(key):
    from langchain_groq import ChatGroq

    return ChatGroq(
        model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
        api_key=key,
        temperature=0,
        timeout=15,
        max_retries=0,
        max_tokens=16,
    )


def mistral(key):
    from langchain_mistralai import ChatMistralAI

    return ChatMistralAI(
        model=os.getenv("MISTRAL_MODEL", "mistral-small-latest"),
        api_key=key,
        temperature=0,
        timeout=15,
        max_retries=0,
        max_tokens=16,
    )


def ollama(key):
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "gpt-oss:120b"),
        base_url=os.getenv("OLLAMA_BASE_URL", "https://ollama.com"),
        client_kwargs={
            "headers": {"Authorization": f"Bearer {key}"},
            "timeout": 15,
        },
        temperature=0,
    )


def huggingface(key):
    from langchain_huggingface import ChatHuggingFace, HuggingFaceEndpoint

    llm = HuggingFaceEndpoint(
        repo_id=os.getenv("HUGGINGFACE_MODEL", "Qwen/Qwen2.5-7B-Instruct"),
        task="text-generation",
        huggingfacehub_api_token=key,
        max_new_tokens=16,
        temperature=0.01,
        timeout=15,
    )
    return ChatHuggingFace(llm=llm)


PROVIDERS = [
    ("openrouter", "OPENROUTER_API_KEY", openrouter),
    ("gemini", "GEMINI_API_KEY", gemini),
    ("groq", "GROQ_API_KEY", groq),
    ("mistral", "MISTRALAI_API_KEY", mistral),
    ("ollama-cloud", "OLLAMA_API_KEY", ollama),
    ("huggingface", "HUGGINGFACE_API_KEY", huggingface),
]

# Keys in backend/.env that are not chat models, so invoke() cannot ping them.
NON_LLM = [
    "GITHUB_TOKEN",
    "ELEVEN_LAB_API_KEY",
    "VOYAGE_API_KEY",
    "LANGSMITH_API_KEY",
    "SENTRY_DSN",
    "POSTGRES_NEON_URL",
]


def ping(name, env_var, build):
    key = os.getenv(env_var, "").strip().strip('"').strip("'")
    if not key:
        return name, "SKIP", "not set"
    try:
        chat = build(key)
        reply = chat.invoke(PROMPT).content
        text = reply if isinstance(reply, str) else str(reply)
        text = " ".join(text.split())[:120]
        verdict = "PASS" if "pong" in text.lower() else "NO PONG"
        return name, verdict, text
    except Exception as exc:  # noqa: BLE001 - report every provider independently
        message = " ".join(str(exc).split())[:200].replace(key, "***")
        return name, "FAIL", f"{type(exc).__name__}: {message}"


def main():
    print(f"{'PROVIDER':<14} {'RESULT':<8} DETAIL", flush=True)
    results = []
    with ThreadPoolExecutor(max_workers=len(PROVIDERS)) as pool:
        futures = [pool.submit(ping, *p) for p in PROVIDERS]
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            name, verdict, detail = result
            print(f"{name:<14} {verdict:<8} {detail}", flush=True)

    working = [name for name, verdict, _ in results if verdict == "PASS"]
    print(f"\nWorking ({len(working)}/{len(PROVIDERS)}): {', '.join(working) or 'none'}")

    skipped = [f"{var}" for var in NON_LLM if os.getenv(var, "").strip()]
    if skipped:
        print(f"Not chat models, not pinged: {', '.join(skipped)}")


if __name__ == "__main__":
    main()
