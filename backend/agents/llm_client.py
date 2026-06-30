#llm_client.py
import os
import json
import base64
import logging
from groq import Groq
from config import settings

logger = logging.getLogger(__name__)

client = Groq(api_key=settings.GROQ_API_KEY)

VISION_MODEL = settings.GROQ_VISION_MODEL
TEXT_MODEL = settings.GROQ_TEXT_MODEL


def encode_image_b64(image_path):
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def call_groq_vision_json(system_prompt, user_text, image_path, retries=2, max_tokens=2048):
    """Send an image + instructions to Llama 4 Scout, expect strict JSON back."""
    b64 = encode_image_b64(image_path)
    ext = os.path.splitext(image_path)[1].lstrip(".").lower() or "jpeg"
    if ext == "jpg":
        ext = "jpeg"
    data_url = f"data:image/{ext};base64,{b64}"

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": user_text},
                {"type": "image_url", "image_url": {"url": data_url}},
            ],
        },
    ]

    for attempt in range(retries + 1):
        try:
            resp = client.chat.completions.create(
                model=VISION_MODEL,
                messages=messages,
                temperature=0,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
                timeout=settings.GROQ_TIMEOUT,
            )
            content = resp.choices[0].message.content
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Groq vision returned non-JSON (attempt {attempt}): {e}")
        except Exception as e:
            logger.error(f"Groq vision call failed (attempt {attempt}): {e}")
        if attempt == retries:
            return None


def call_groq_text_json(system_prompt, user_text, retries=2, max_tokens=2048):
    """Text-only Groq call (used by validation agent's review pass)."""
    for attempt in range(retries + 1):
        try:
            resp = client.chat.completions.create(
                model=TEXT_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_text},
                ],
                temperature=0,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
                timeout=settings.GROQ_TIMEOUT,
            )
            return json.loads(resp.choices[0].message.content)
        except Exception as e:
            logger.error(f"Groq text call failed (attempt {attempt}): {e}")
        if attempt == retries:
            return None