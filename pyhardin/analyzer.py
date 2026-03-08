import json
import re
import time

from google import genai
from openai import OpenAI

from pyhardin.config import get_api_base, get_api_key, get_model, get_provider
from pyhardin.exceptions import AnalyzerError, APIRateLimitError
from pyhardin.scanner import ServiceConfig
from pyhardin.state import AnalysisResult, Finding

SYSTEM_PROMPT = """You are Pyhardin, an expert Linux security auditor. You analyze configuration files
for security misconfigurations, hardening opportunities, and best practices violations.

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


def build_prompt(service: ServiceConfig) -> str:
    """Generates the exact LLM prompt for the given service config."""
    os_info_str = ""
    if service.os_context:
        os_info_str = "\n".join(f"{k}: {v}" for k, v in service.os_context.items())
    if not os_info_str:
        os_info_str = "Unknown Linux"

    parts = [
        f"Analyze the following configuration files for the '{service.service_name}' service:\n",
        f"Server OS Context:\n{os_info_str}\n\n",
        "Provide your remediation_command specific to the Server OS Context "
        "(e.g. use apt-get vs dnf where appropriate).\n"
    ]
    for filepath, content in service.contents.items():
        parts.append(f"--- FILE: {filepath} ---")

        cleaned_lines = []
        for line in content.splitlines():
            stripped = line.strip()
            # Skip empty lines and full-line comments
            if stripped and not stripped.startswith('#'):
                cleaned_lines.append(line)

        parts.append("\n".join(cleaned_lines))
        parts.append(f"--- END FILE: {filepath} ---\n")
    parts.append("Respond with the JSON format specified in your instructions.")
    return "\n".join(parts)


def _parse_response(raw: str, service_name: str) -> AnalysisResult:
    result = AnalysisResult(service_name=service_name)
    cleaned = raw.strip()

    # Often models with thinking enabled put JSON in markdown blocks.
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', cleaned, re.DOTALL)
    if not json_match:
        # Fallback: find the first occurrence of `{"service"` or `{` and the last `}`.
        start_idx = cleaned.find('{"service"')
        if start_idx == -1:
            start_idx = cleaned.find('{')

        end_idx = cleaned.rfind('}')
        if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
            json_string = cleaned[start_idx:end_idx + 1]
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
        parsed_findings = []

        for f in findings_list:
            finding = Finding(
                title=f.get("title", "Unknown"),
                severity=f.get("severity", "info").upper(),
                description=f.get("description", ""),
                file=f.get("file", ""),
                current_value=f.get("current_value", ""),
                recommended_value=f.get("recommended_value", ""),
                remediation_command=f.get("remediation_command", "")
            )
            parsed_findings.append(finding)
            if finding.remediation_command:
                remediation.append(finding.remediation_command)

        result.summary = data.get("summary", "")
        result.findings = parsed_findings
        result.remediation_commands = remediation

    except (json.JSONDecodeError, KeyError):
        result.findings = "Failed to parse JSON. Raw output:\n" + cleaned

    return result


def analyze_service(
        target: ServiceConfig | AnalysisResult, max_retries: int = 3
) -> AnalysisResult:
    api_key = get_api_key()
    if not api_key:
        raise AnalyzerError("No API key configured. Run 'pyhardin' to set up.", code="NO_API_KEY")

    provider = get_provider()
    model_name = get_model()
    api_base = get_api_base()

    # Extract prompt depending on what was passed.
    if isinstance(target, ServiceConfig):
        prompt = build_prompt(target)
        service_name = target.service_name
    else:  # target is an AnalysisResult.
        if not target.prompt:
            raise AnalyzerError(
                "AnalysisResult provided without a prompt string.",
                code="MISSING_PROMPT_IN_ANALYSIS_RESULT"
            )
        prompt = target.prompt
        service_name = target.service_name

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
                raw_text = (
                    openai_response.choices[0].message.content
                    if openai_response.choices and openai_response.choices[0].message.content
                    else ""
                )
            else:
                raise AnalyzerError(f"Unknown provider: {provider}", code="INVALID_PROVIDER")

            result = _parse_response(raw_text, service_name)
            result.prompt = prompt
            result.provider = provider
            result.model = model_name
            result.temperature = 0.1
            result.max_tokens = 16384 if provider == "gemini" else 4096  # Default estimation for OpenAI if not set.
            return result

        except Exception as e:
            error_str = str(e)
            error_lower = error_str.lower()

            # Fail fast for permanent quota/balance issues.
            if "insufficient_quota" in error_lower or "insufficient balance" in error_lower or "exceeded your current quota" in error_lower:
                raise APIRateLimitError(message=error_str, retry_after=0) from e

            if "rate" in error_lower or "429" in error_lower or "quota" in error_lower:
                wait_time = (2 ** attempt) * 10  # Reduced from 30 to 10 for better GUI responsiveness
                if attempt < max_retries - 1:
                    time.sleep(wait_time)
                    continue
                raise APIRateLimitError(message=error_str, retry_after=wait_time) from e
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise AnalyzerError(
                f"Failed to analyze {service_name}: {e}",
                code="ANALYSIS_FAIL",
                details={"service": service_name},
            ) from e

    raise AnalyzerError(
        f"Exhausted retries for {service_name}",
        code="MAX_RETRIES",
    )
