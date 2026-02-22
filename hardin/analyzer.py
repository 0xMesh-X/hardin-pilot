import json
import re
import time

from google import genai
from openai import OpenAI

from hardin.config import get_api_base, get_api_key, get_model, get_provider
from hardin.exceptions import AnalyzerError, APIRateLimitError
from hardin.scanner import ServiceConfig
from hardin.state import AnalysisResult

SYSTEM_PROMPT = """You are Hardin, an expert Linux security auditor. You analyze configuration files for security misconfigurations, hardening opportunities, and best practices violations.

For each configuration you analyze, you MUST respond in the following JSON format ONLY:
{
  "service": "<service_name>",
  "risk_level": "critical|high|medium|low|info",
  "findings": [
    {
      "title": "<short title>",
      "severity": "critical|high|medium|low|info",
      "description": "<what is wrong and why it matters>",
      "file": "<affected file path>",
      "current_value": "<current misconfigured value or setting>",
      "recommended_value": "<what it should be>",
      "remediation_command": "<exact shell command to fix this issue>"
    }
  ],
  "summary": "<overall security posture summary for this service>"
}

Rules:
- Every remediation_command must be a valid, safe shell command that fixes the specific issue.
- Use sed, echo, or direct config edit commands.
- Always backup files before modifying: use cp commands before sed.
- If no issues are found, return an empty findings array with a positive summary.
- Be thorough: check permissions, authentication, encryption, logging, and access controls.
- Focus on real, actionable security issues, not style preferences."""


def _build_prompt(service: ServiceConfig) -> str:
    parts = [f"Analyze the following configuration files for the '{service.service_name}' service:\n"]
    for filepath, content in service.contents.items():
        parts.append(f"--- FILE: {filepath} ---")
        parts.append(content)
        parts.append(f"--- END FILE: {filepath} ---\n")
    parts.append("Respond with the JSON format specified in your instructions.")
    return "\n".join(parts)


def _parse_response(raw: str, service_name: str) -> AnalysisResult:
    result = AnalysisResult(service_name=service_name)
    cleaned = raw.strip()

    # Often models with thinking enabled put JSON in markdown blocks
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', cleaned, re.DOTALL)
    if not json_match:
        # Fallback: find the first occurrence of `{"service"` or `{` and the last `}`.
        start_idx = cleaned.find('{"service"')
        if start_idx == -1:
            start_idx = cleaned.find('{')

        end_idx = cleaned.rfind('}')
        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
            json_string = cleaned[start_idx:end_idx+1]
        else:
            json_string = None
    else:
        json_string = json_match.group(1)

    if not json_string:
        result.findings = cleaned
        return result

    try:
        data = json.loads(json_string)
        findings_list = data.get("findings", [])
        remediation = []
        finding_texts = []

        for f in findings_list:
            severity = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            desc = f.get("description", "")
            fpath = f.get("file", "")
            current = f.get("current_value", "")
            recommended = f.get("recommended_value", "")
            cmd = f.get("remediation_command", "")

            finding_texts.append(
                f"[{severity}] {title}\n"
                f"  File: {fpath}\n"
                f"  Issue: {desc}\n"
                f"  Current: {current}\n"
                f"  Recommended: {recommended}\n"
            )
            if cmd:
                remediation.append(cmd)

        summary = data.get("summary", "")
        # Add summary and all detailed finding texts
        result.findings = summary + "\n\n" + "\n\n".join(finding_texts)
        result.remediation_commands = remediation

    except (json.JSONDecodeError, KeyError):
        result.findings = "Failed to parse JSON. Raw output:\n" + cleaned

    return result


def analyze_service(service: ServiceConfig, max_retries: int = 3) -> AnalysisResult:
    api_key = get_api_key()
    if not api_key:
        raise AnalyzerError("No API key configured. Run 'hardin' to set up.", code="NO_API_KEY")

    provider = get_provider()
    model_name = get_model()
    api_base = get_api_base()
    prompt = _build_prompt(service)

    for attempt in range(max_retries):
        try:
            if provider == "gemini":
                gemini_client = genai.Client(api_key=api_key)
                gemini_response = gemini_client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=genai.types.GenerateContentConfig(
                        system_instruction=SYSTEM_PROMPT,
                        temperature=0.1,
                        max_output_tokens=16384,
                        response_mime_type="application/json",
                        thinking_config=genai.types.ThinkingConfig(
                            thinking_budget=8192,
                        ),
                    ),
                )
                raw_text = gemini_response.text if gemini_response.text else ""
            elif provider == "openai":
                if api_base:
                    openai_client = OpenAI(api_key=api_key, base_url=api_base)
                else:
                    openai_client = OpenAI(api_key=api_key)

                openai_response = openai_client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1,
                )
                raw_text = openai_response.choices[0].message.content if openai_response.choices and openai_response.choices[0].message.content else ""
            else:
                raise AnalyzerError(f"Unknown provider: {provider}", code="INVALID_PROVIDER")

            return _parse_response(raw_text, service.service_name)

        except Exception as e:
            error_str = str(e).lower()
            if "rate" in error_str or "429" in error_str or "quota" in error_str:
                wait_time = (2 ** attempt) * 30
                if attempt < max_retries - 1:
                    time.sleep(wait_time)
                    continue
                raise APIRateLimitError(retry_after=wait_time) from e
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise AnalyzerError(
                f"Failed to analyze {service.service_name}: {e}",
                code="ANALYSIS_FAIL",
                details={"service": service.service_name},
            ) from e

    raise AnalyzerError(
        f"Exhausted retries for {service.service_name}",
        code="MAX_RETRIES",
    )
