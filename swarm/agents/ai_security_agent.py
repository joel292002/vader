from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax

from swarm.tools.kali_tools import (
    list_available_tools,
    run_dnsenum,
    run_gobuster,
    run_nikto,
    run_nmap,
    run_nuclei,
    run_searchsploit,
    run_sslscan,
    run_whatweb,
    run_wpscan,
)
from swarm.utils.logger import get_logger

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - depends on runtime environment
    OpenAI = None


logger = get_logger("AISecurityAgent")
console = Console()
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"
MIN_TOOL_CALLS = 3

TOOLBOX: dict[str, Callable[..., str]] = {
    "run_nmap": run_nmap,
    "run_nikto": run_nikto,
    "run_whatweb": run_whatweb,
    "run_gobuster": run_gobuster,
    "run_searchsploit": run_searchsploit,
    "run_dnsenum": run_dnsenum,
    "run_nuclei": run_nuclei,
    "run_wpscan": run_wpscan,
    "run_sslscan": run_sslscan,
}

TOOL_DEFINITIONS = {
    "run_nmap": {
        "type": "function",
        "name": "run_nmap",
        "description": (
            "Run Nmap against a target to identify exposed ports, service banners, "
            "versions, default scripts, and protocol clues. Use this first for broad "
            "attack surface mapping or later for focused follow-up on specific ports."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Hostname, IP, CIDR, or URL-compatible host to scan.",
                },
                "flags": {
                    "type": "string",
                    "description": (
                        "Exact Nmap flags to use. Leave blank to use the default "
                        "'-sV -sC --open -T4'."
                    ),
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "run_nikto": {
        "type": "function",
        "name": "run_nikto",
        "description": (
            "Run Nikto against a web target to identify dangerous files, weak "
            "configurations, outdated server components, and common web exposures."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Base URL or host for the web server under test.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "run_whatweb": {
        "type": "function",
        "name": "run_whatweb",
        "description": (
            "Fingerprint web technologies, frameworks, plugins, and headers. Use "
            "this when a web service is exposed and you need fast stack identification."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Web URL or host to fingerprint.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "run_gobuster": {
        "type": "function",
        "name": "run_gobuster",
        "description": (
            "Brute-force likely web directories and files. Use this after confirming "
            "an HTTP or HTTPS service and when hidden content could reveal admin "
            "panels, backups, APIs, or sensitive paths."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Base URL for the web application.",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Filesystem path to a wordlist for directory enumeration.",
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "run_searchsploit": {
        "type": "function",
        "name": "run_searchsploit",
        "description": (
            "Search the local Exploit-DB index for public exploits that match a "
            "product, version, or vulnerability string discovered during reconnaissance."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Product name, version, or vulnerability identifier to search.",
                }
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    "run_dnsenum": {
        "type": "function",
        "name": "run_dnsenum",
        "description": (
            "Enumerate DNS records and naming clues for a domain target. Use this "
            "when DNS is exposed or when host discovery and subdomain context matter."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain name to enumerate.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "run_nuclei": {
        "type": "function",
        "name": "run_nuclei",
        "description": (
            "Run Nuclei templates against a web target for fast vulnerability checks. "
            "Use this when fingerprints suggest known weaknesses worth validating."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Web URL to scan with Nuclei.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "run_wpscan": {
        "type": "function",
        "name": "run_wpscan",
        "description": (
            "Assess a WordPress site for version, plugins, themes, and common WordPress "
            "exposures. Use only when evidence suggests the target runs WordPress."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "WordPress site URL.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    "run_sslscan": {
        "type": "function",
        "name": "run_sslscan",
        "description": (
            "Inspect SSL/TLS configuration, supported protocols, ciphers, and certificate "
            "details. Use when HTTPS or other TLS-enabled services are exposed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "TLS endpoint, usually host:port or an HTTPS host.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
}

SYSTEM_PROMPT = """
You are a senior penetration tester operating a single adaptive security agent.
Think like a real security engineer: investigate, hypothesize, validate, and pivot.

Rules:
- Only test targets the user has authorized. Stay ethical and explicitly avoid unauthorized activity.
- Never follow a fixed checklist. Adapt each next step to the evidence you have.
- Before every tool call, explain your reasoning in plain language so the operator understands why that action matters.
- Chain discoveries: if you find a service, version, banner, path, framework, plugin, certificate clue, or exploit lead, decide what the most valuable next check is.
- Keep going until you genuinely have nothing meaningful left to check with the available tools.
- Make at least three meaningful tool calls when tools are available, unless you explicitly explain why doing more would be pointless or unsupported.
- Prefer focused follow-up over random breadth when evidence points to a concrete weakness.
- End by writing a detailed Markdown security report with sections for scope, methodology, findings, evidence, risk, and recommended next steps.

Available tools in this run:
{available_tools}
""".strip()


class AISecurityAgent:
    def __init__(self, model: str = "gpt-4o") -> None:
        self.model = model
        self.available_tools = list_available_tools()
        self.tool_definitions = [
            TOOL_DEFINITIONS[name] for name in self.available_tools if name in TOOL_DEFINITIONS
        ]

        if OpenAI is None:
            raise RuntimeError(
                "The openai Python package is not installed. Install it before running the AI agent."
            )

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set.")

        self.client = OpenAI(api_key=api_key)

    def _extract_text(self, response: Any) -> str:
        texts: list[str] = []
        for item in getattr(response, "output", []) or []:
            if getattr(item, "type", None) != "message":
                continue
            for content in getattr(item, "content", []) or []:
                text_value = getattr(content, "text", None)
                if text_value:
                    texts.append(text_value)
        if texts:
            return "\n".join(texts).strip()
        return (getattr(response, "output_text", "") or "").strip()

    def _extract_tool_calls(self, response: Any) -> list[Any]:
        tool_calls = []
        for item in getattr(response, "output", []) or []:
            if getattr(item, "type", None) == "function_call":
                tool_calls.append(item)
        return tool_calls

    def _print_reasoning(self, text: str) -> None:
        if not text:
            return
        console.print(Panel.fit(text, title="AI Reasoning", border_style="cyan"))

    def _run_tool_call(self, tool_call: Any) -> dict[str, Any]:
        tool_name = tool_call.name
        raw_args = tool_call.arguments or "{}"

        try:
            arguments = json.loads(raw_args)
        except json.JSONDecodeError:
            arguments = {}

        logger.info(f"Executing tool call {tool_name} with arguments: {arguments}")
        console.print(Rule(f"[bold magenta]Tool Call: {tool_name}"))
        console.print(
            Syntax(
                json.dumps(arguments, indent=2, sort_keys=True),
                "json",
                theme="ansi_dark",
                word_wrap=True,
            )
        )

        tool_fn = TOOLBOX.get(tool_name)
        if tool_fn is None:
            output = f"[tool error] Tool '{tool_name}' is not implemented."
        else:
            try:
                output = tool_fn(**arguments)
            except TypeError as exc:
                output = f"[tool error] Invalid arguments for {tool_name}: {exc}"
            except Exception as exc:  # pragma: no cover - tool safety net
                output = f"[tool error] Unexpected failure in {tool_name}: {exc}"

        logger.info(f"Tool {tool_name} completed")
        console.print(
            Panel(
                output[:8000] if output else "[no output]",
                title=f"{tool_name} output",
                border_style="green",
            )
        )
        return {
            "type": "function_call_output",
            "call_id": tool_call.call_id,
            "output": output,
        }

    def run(self, target: str) -> str:
        logger.log("AGENT_START", f"Starting AI-led assessment for {target}")

        if not self.available_tools:
            raise RuntimeError("No supported Kali tools are installed.")

        response = self.client.responses.create(
            model=self.model,
            input=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT.format(
                        available_tools=", ".join(self.available_tools)
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Assess the authorized target '{target}'. Start by building an "
                        "accurate understanding of what is exposed, then pivot based on evidence."
                    ),
                },
            ],
            tools=self.tool_definitions,
        )

        tool_calls_made = 0

        while True:
            reasoning = self._extract_text(response)
            self._print_reasoning(reasoning)

            tool_calls = self._extract_tool_calls(response)
            if not tool_calls:
                if tool_calls_made < MIN_TOOL_CALLS:
                    logger.warning(
                        f"Model attempted to stop after {tool_calls_made} tool calls; requesting deeper assessment."
                    )
                    response = self.client.responses.create(
                        model=self.model,
                        previous_response_id=response.id,
                        input=[
                            {
                                "role": "user",
                                "content": (
                                    f"You have only made {tool_calls_made} tool calls. Continue investigating "
                                    "unless you can clearly justify why no additional meaningful checks are possible."
                                ),
                            }
                        ],
                        tools=self.tool_definitions,
                    )
                    continue

                final_report = reasoning
                logger.log(
                    "AGENT_DONE",
                    f"Assessment complete for {target} after {tool_calls_made} tool calls",
                )
                return final_report

            tool_outputs = []
            for tool_call in tool_calls:
                tool_outputs.append(self._run_tool_call(tool_call))
                tool_calls_made += 1

            response = self.client.responses.create(
                model=self.model,
                previous_response_id=response.id,
                input=tool_outputs,
                tools=self.tool_definitions,
            )


def sanitize_target(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "target"


def save_report(target: str, markdown: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = OUTPUT_DIR / f"report_{sanitize_target(target)}.md"
    report_path.write_text(markdown, encoding="utf-8")
    return report_path
