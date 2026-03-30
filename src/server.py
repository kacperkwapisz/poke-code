#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone


import httpx
import uvicorn
import yaml
from fastmcp import Context, FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from starlette.middleware import Middleware
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send


# ---------------------------------------------------------------------------
# Subprocess stream buffer limit (default 64 KB is too small for large JSON
# event lines that may embed full file contents).
# ---------------------------------------------------------------------------

_SUBPROCESS_STREAM_LIMIT = 10 * 1024 * 1024  # 10 MB

# ---------------------------------------------------------------------------
# Structured JSON logging
# ---------------------------------------------------------------------------


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if hasattr(record, "run_id"):
            entry["run_id"] = record.run_id
        if record.exc_info and record.exc_info[0]:
            entry["error"] = self.formatException(record.exc_info)
        return json.dumps(entry)


handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logging.root.handlers = [handler]
logging.root.setLevel(logging.INFO)
logger = logging.getLogger("poke-code")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class ApiKeyAuth(TokenVerifier):
    def __init__(self, api_key: str):
        super().__init__()
        self._api_key = api_key

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token, self._api_key):
            return AccessToken(token=token, client_id="owner", scopes=["all"])
        return None


# ---------------------------------------------------------------------------
# Route filter
# ---------------------------------------------------------------------------


class DropNonMCPRoutes:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http" and not (
            scope["path"].startswith("/mcp") or scope["path"].startswith("/auth/")
        ):
            response = Response(status_code=404)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_config() -> dict:
    path = os.environ.get("CONFIG_PATH", "config.yml")
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("Config file %s not found, using defaults/env vars", path)
        return {}


# ---------------------------------------------------------------------------
# Constants & validation
# ---------------------------------------------------------------------------

MAX_ACTIVITY_LOG_ENTRIES = 500
MAX_COMPLETED_RUNS = 50

# Secrets to strip from env passed to Claude subprocess
_SECRET_ENV_KEYS = {"MCP_API_KEY", "WEBHOOK_BEARER_TOKEN", "CONTEXT7_API_KEY"}

_SAFE_REPO_URL = re.compile(
    r"^https?://[a-zA-Z0-9._\-]+(?::\d+)?/[a-zA-Z0-9._\-/]+(?:\.git)?$"
)

_CONTEXT7_PROMPT = (
    "Always use Context7 MCP tools (resolve-library-id, query-docs) when you need "
    "library/API documentation, code generation examples, setup or configuration steps. "
    "Do this automatically without the user having to explicitly ask."
)

# ---------------------------------------------------------------------------
# OpenCode provider auth
# ---------------------------------------------------------------------------

_OPENCODE_AUTH_FILE = os.path.expanduser("~/.local/share/opencode/auth.json")

_OPENCODE_PROVIDERS = {
    "opencode": {"env": "OPENCODE_API_KEY", "auth_key": "opencode", "type": "api"},
    "openai": {"env": "OPENAI_API_KEY", "auth_key": "openai", "type": "oauth_device"},
    "anthropic": {"env": "ANTHROPIC_API_KEY", "auth_key": "anthropic", "type": "oauth_redirect"},
    "google": {"env": "GEMINI_API_KEY", "auth_key": "google", "type": "oauth_redirect"},
    "github-copilot": {"env": "GITHUB_TOKEN", "auth_key": "github-copilot", "type": "oauth_device"},
    "deepseek": {"env": "DEEPSEEK_API_KEY", "auth_key": "deepseek", "type": "api"},
    "groq": {"env": "GROQ_API_KEY", "auth_key": "groq", "type": "api"},
    "openrouter": {"env": "OPENROUTER_API_KEY", "auth_key": "openrouter", "type": "api"},
    "together": {"env": "TOGETHER_API_KEY", "auth_key": "together", "type": "api"},
    "xai": {"env": "XAI_API_KEY", "auth_key": "xai", "type": "api"},
    "fireworks": {"env": "FIREWORKS_API_KEY", "auth_key": "fireworks", "type": "api"},
    "aws-bedrock": {"env": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], "type": "env_only"},
    "azure-openai": {"env": ["AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY"], "type": "env_only"},
    "google-vertex": {"env": ["GOOGLE_CLOUD_PROJECT"], "type": "env_only"},
}

# OAuth constants (public client IDs from community auth plugins)
_OPENAI_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
_OPENAI_DEVICE_AUTH_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
_OPENAI_TOKEN_URL = "https://auth.openai.com/oauth/token"

_ANTHROPIC_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
_ANTHROPIC_AUTHORIZE_URLS = {
    "max": "https://claude.ai/oauth/authorize",
    "console": "https://platform.claude.com/oauth/authorize",
}
_ANTHROPIC_TOKEN_URL = "https://platform.claude.com/v1/oauth/token"

_GOOGLE_CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
_GOOGLE_CLIENT_SECRET = "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"
_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Flow expiry
_DEVICE_FLOW_TTL = 900  # 15 minutes
_REDIRECT_FLOW_TTL = 300  # 5 minutes
_API_KEY_FLOW_TTL = 600  # 10 minutes

_auth_json_lock = threading.Lock()
_auth_flows: dict[str, dict] = {}  # module-level so HTTP routes can access


def _read_auth_json() -> dict:
    """Read OpenCode's auth.json credentials file."""
    try:
        with open(_OPENCODE_AUTH_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _write_auth_json(data: dict) -> None:
    """Write to OpenCode's auth.json, merging with existing data."""
    with _auth_json_lock:
        os.makedirs(os.path.dirname(_OPENCODE_AUTH_FILE), exist_ok=True)
        existing = _read_auth_json()
        existing.update(data)
        with open(_OPENCODE_AUTH_FILE, "w") as f:
            json.dump(existing, f, indent=2)


def _remove_auth_json_key(key: str) -> bool:
    """Remove a provider key from auth.json. Returns True if key existed."""
    with _auth_json_lock:
        data = _read_auth_json()
        if key not in data:
            return False
        del data[key]
        os.makedirs(os.path.dirname(_OPENCODE_AUTH_FILE), exist_ok=True)
        with open(_OPENCODE_AUTH_FILE, "w") as f:
            json.dump(data, f, indent=2)
        return True


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_env() -> dict[str, str]:
    """Return current env minus secrets — safe to pass to subprocesses."""
    return {k: v for k, v in os.environ.items() if k not in _SECRET_ENV_KEYS}


def _subprocess_env(config: dict) -> dict[str, str]:
    """Build env for subprocesses — safe env + webhook token + provider env."""
    env = _safe_env()
    bearer_token = config.get("webhook_bearer_token", "")
    if bearer_token:
        env["POKE_WEBHOOK_TOKEN"] = bearer_token
    # Forward explicit provider env vars from config
    provider_env = config.get("opencode", {}).get("provider_env", {})
    for key, value in provider_env.items():
        if isinstance(key, str) and isinstance(value, str) and value:
            env[key] = value
    return env


# ---------------------------------------------------------------------------
# Run state
# ---------------------------------------------------------------------------


@dataclass
class RunState:
    run_id: str
    repo_url: str
    repo_path: str
    status: str = "ready"  # ready, running, completed, failed, cancelled
    phase: str = "idle"  # cloning, idle, thinking, using_tool, editing_files, complete
    engine: str = "claude"  # "claude" or "opencode"
    model: str = ""
    task: asyncio.Task | None = field(default=None, repr=False)
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _process: asyncio.subprocess.Process | None = field(default=None, repr=False)
    activity_log: list[dict] = field(default_factory=list)
    files_modified: set[str] = field(default_factory=set)
    current_tool: str | None = None
    current_file: str | None = None
    turns_used: int = 0
    turns_max: int = 50
    cost_usd: float = 0.0
    budget_usd: float = 1.0
    tokens_used: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    created_at: str = field(default_factory=_now)
    started_at: str | None = None
    completed_at: str | None = None
    result_summary: str | None = None
    execution_mode: str = "full"  # "plan" | "implement" | "full"
    plan_text: str | None = None
    plan_status: str | None = None  # None | "pending_review" | "approved" | "rejected"
    _next_seq: int = 0

    def add_activity(self, entry: dict) -> None:
        entry.setdefault("ts", _now())
        entry["seq"] = self._next_seq
        self._next_seq += 1
        self.activity_log.append(entry)
        if len(self.activity_log) > MAX_ACTIVITY_LOG_ENTRIES:
            self.activity_log = self.activity_log[-MAX_ACTIVITY_LOG_ENTRIES:]

    def to_status_dict(self) -> dict:
        start = datetime.fromisoformat(self.started_at) if self.started_at else None
        duration = (datetime.now(timezone.utc) - start).total_seconds() if start else 0
        return {
            "run_id": self.run_id,
            "repo_url": self.repo_url,
            "status": self.status,
            "phase": self.phase,
            "engine": self.engine,
            "model": self.model or None,
            "current_tool": self.current_tool,
            "current_file": self.current_file,
            "turns_used": self.turns_used,
            "turns_max": self.turns_max,
            "cost_usd": self.cost_usd,
            "budget_usd": self.budget_usd,
            "tokens_used": self.tokens_used,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "duration_seconds": round(duration, 1),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "recent_activity": self.activity_log[-10:],
            "files_modified": sorted(self.files_modified),
            "summary_so_far": self.result_summary,
            "execution_mode": self.execution_mode,
            "plan_status": self.plan_status,
            "plan_text": self.plan_text[:1000] if self.plan_text else None,
        }

    def to_summary_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "repo_url": self.repo_url,
            "status": self.status,
            "engine": self.engine,
            "model": self.model or None,
            "turns_used": self.turns_used,
            "cost_usd": self.cost_usd,
            "tokens_used": self.tokens_used,
            "created_at": self.created_at,
            "execution_mode": self.execution_mode,
            "plan_status": self.plan_status,
        }


# ---------------------------------------------------------------------------
# Plan mode
# ---------------------------------------------------------------------------

def _write_claude_settings(repo_path: str, run_id: str, config: dict) -> None:
    """Write .claude/settings.json with webhook hooks when webhook_url is configured."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return

    hooks_dir = os.path.join(repo_path, ".claude")
    os.makedirs(hooks_dir, exist_ok=True)

    hook_script = os.path.join(hooks_dir, "poke-hook.sh")
    with open(hook_script, "w") as f:
        f.write(f"""#!/bin/sh
EVENT_TYPE="${{1:-unknown}}"
PAYLOAD=$(cat <<HOOKEOF
{{"run_id":"{run_id}","type":"hook","event":"$EVENT_TYPE","tool_name":"$CLAUDE_TOOL_NAME","file_path":"$CLAUDE_FILE_PATH","ts":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}}
HOOKEOF
)
AUTH_HEADER=""
if [ -n "$POKE_WEBHOOK_TOKEN" ]; then
  AUTH_HEADER="-H Authorization:\\ Bearer\\ $POKE_WEBHOOK_TOKEN"
fi
curl -sf -X POST '{webhook_url}' -H 'Content-Type: application/json' $AUTH_HEADER -d "$PAYLOAD" >/dev/null 2>&1 &
""")
    os.chmod(hook_script, 0o755)

    hook_tools = {
        "Read": "read", "Glob": "glob", "Grep": "grep", "Bash": "bash",
        "WebSearch": "web_search", "Task": "subagent",
        "EditTool": "edit", "WriteTool": "write", "Stop": "stop",
    }
    poke_hooks = {
        tool: [{"matcher": "", "hooks": [{"type": "command", "command": f"{hook_script} {event}"}]}]
        for tool, event in hook_tools.items()
    }

    # Merge with existing settings if present
    settings_path = os.path.join(hooks_dir, "settings.json")
    existing: dict = {}
    if os.path.isfile(settings_path):
        try:
            with open(settings_path) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    existing.setdefault("hooks", {}).update(poke_hooks)
    with open(settings_path, "w") as f:
        json.dump(existing, f)


def _build_mcp_config(config: dict) -> str | None:
    """Return a JSON string for --mcp-config with MCP servers."""
    servers: dict = {
        "medusa": {
            "type": "url",
            "url": "https://docs.medusajs.com/mcp",
        },
    }
    key = config.get("context7_api_key") or os.environ.get("CONTEXT7_API_KEY", "")
    if key:
        servers["context7"] = {
            "type": "url",
            "url": "https://mcp.context7.com/mcp",
            "headers": {"CONTEXT7_API_KEY": key},
        }
    return json.dumps({"mcpServers": servers})


def _write_opencode_config(repo_path: str, config: dict) -> None:
    """Write opencode.json with MCP config in workspace root, merging with existing."""
    key = config.get("context7_api_key") or os.environ.get("CONTEXT7_API_KEY", "")

    oc_path = os.path.join(repo_path, "opencode.json")
    existing: dict = {}
    if os.path.isfile(oc_path):
        try:
            with open(oc_path) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    mcp = existing.setdefault("mcp", {})
    if key:
        mcp["context7"] = {
            "type": "remote",
            "url": "https://mcp.context7.com/mcp",
            "headers": {"CONTEXT7_API_KEY": key},
            "enabled": True,
        }
    mcp["medusa"] = {
        "type": "remote",
        "url": "https://docs.medusajs.com/mcp",
        "enabled": True,
    }
    with open(oc_path, "w") as f:
        json.dump(existing, f)


_PLAN_ONLY_PREFIX = """You are in PLANNING MODE. Analyze the codebase and produce a detailed implementation plan.

RULES:
- Do NOT create, edit, write, or modify any files
- Only use Read, Glob, Grep to explore the codebase
- Output a structured plan: summary, files to modify, step-by-step approach, risks"""


# ---------------------------------------------------------------------------
# Claude Code CLI runner
# ---------------------------------------------------------------------------


def _handle_claude_event(run: RunState, event: dict) -> None:
    event_type = event.get("type", "")

    if event_type == "assistant":
        run.turns_used += 1
        run.phase = "thinking"
        message = event.get("message", {})
        if not run.model and message.get("model"):
            run.model = message["model"]
        for block in message.get("content", []):
            block_type = block.get("type", "")
            if block_type == "text":
                text = block.get("text", "").strip()
                if text:
                    run.result_summary = text[:200]
                    run.add_activity({"type": "text", "detail": text[:300]})
                    if run.execution_mode == "plan":
                        run.plan_text = (run.plan_text or "") + text + "\n"
            elif block_type == "tool_use":
                tool_name = block.get("name", "unknown")
                run.current_tool = tool_name
                run.phase = "using_tool"
                tool_input = block.get("input", {})
                if isinstance(tool_input, dict):
                    file_path = tool_input.get("file_path") or tool_input.get("file") or tool_input.get("path")
                else:
                    file_path = None
                if file_path and tool_name in ("Edit", "Write"):
                    run.files_modified.add(file_path)
                    run.current_file = file_path
                    run.phase = "editing_files"
                run.add_activity({
                    "type": "tool_start",
                    "tool": tool_name,
                    "input": {k: v for k, v in tool_input.items() if k != "content"} if isinstance(tool_input, dict) else {},
                })

    elif event_type == "user":
        # Tool results coming back — mark tool as finished
        if run.current_tool:
            run.add_activity({
                "type": "tool_end",
                "tool": run.current_tool,
                "detail": f"Finished {run.current_tool}",
            })
            run.current_tool = None
            run.current_file = None
            run.phase = "thinking"

    elif event_type == "result":
        if event.get("model"):
            run.model = event["model"]
        run.cost_usd = event.get("total_cost_usd", 0.0)
        run.turns_used = event.get("num_turns", run.turns_used)
        usage = event.get("usage", {})
        run.input_tokens = usage.get("input_tokens", 0)
        run.output_tokens = usage.get("output_tokens", 0)
        run.tokens_used = run.input_tokens + run.output_tokens
        result_text = event.get("result", "")
        if result_text:
            run.result_summary = result_text[:500]
        if run.execution_mode == "plan" and result_text and not event.get("is_error"):
            run.plan_text = result_text
            run.plan_status = "pending_review"
        if event.get("is_error"):
            run.status = "failed"
            run.add_activity({"type": "result", "subtype": "error", "detail": result_text or "Unknown error"})
        else:
            run.status = "completed"
            run.add_activity({"type": "result", "subtype": "success", "detail": result_text or "Task completed"})
        run.phase = "complete"
        run.completed_at = _now()


async def run_claude_task(
    run: RunState,
    task_description: str,
    config: dict,
    http_client: httpx.AsyncClient,
    system_prompt: str | None = None,
    model_override: str | None = None,
) -> None:
    claude_config = config.get("claude", {})
    allowed_tools = claude_config.get("allowed_tools", [
        "Read", "Edit", "Write", "Glob", "Grep",
    ])
    disallowed_tools = claude_config.get("disallowed_tools", [])
    run.turns_max = claude_config.get("default_max_turns", 50)
    run.budget_usd = claude_config.get("default_max_budget_usd", 1.0)
    progress_interval = config.get("webhook_progress_interval", 10)

    # Plan mode: restrict to read-only tools
    if run.execution_mode == "plan":
        allowed_tools = ["Read", "Glob", "Grep"]
        disallowed_tools = ["Edit", "Write"]
        system_prompt = _PLAN_ONLY_PREFIX + ("\n\n" + system_prompt if system_prompt else "")

    run.status = "running"
    run.phase = "thinking"
    run.started_at = _now()
    run.add_activity({"type": "start", "detail": f"Task execution started (mode={run.execution_mode})"})

    cmd: list[str] = [
        "claude", "-p", task_description,
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(run.turns_max),
    ]
    if model_override:
        cmd.extend(["--model", model_override])
    if run.budget_usd:
        cmd.extend(["--max-budget-usd", str(run.budget_usd)])
    if allowed_tools:
        cmd.extend(["--allowedTools", ",".join(allowed_tools)])
    if disallowed_tools:
        cmd.extend(["--disallowedTools", ",".join(disallowed_tools)])
    if system_prompt:
        cmd.extend(["--append-system-prompt", system_prompt])

    mcp_config_json = _build_mcp_config(config)
    cmd.extend(["--mcp-config", mcp_config_json])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=run.repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_subprocess_env(config),
            limit=_SUBPROCESS_STREAM_LIMIT,
        )
        run._process = proc

        assert proc.stdout is not None
        last_webhook_turn = 0
        while True:
            if run._cancel_event.is_set():
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
                break

            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if not line:
                break

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            _handle_claude_event(run, event)

            # Fire per-event webhook for tool use (fire-and-forget)
            event_type = event.get("type", "")
            if event_type == "assistant":
                for block in event.get("message", {}).get("content", []):
                    if block.get("type") == "tool_use":
                        tool_input = block.get("input", {})
                        file_path = None
                        if isinstance(tool_input, dict):
                            file_path = tool_input.get("file_path") or tool_input.get("file") or tool_input.get("path")
                        asyncio.create_task(_fire_event_webhook(
                            run, "tool_use",
                            {"tool_name": block.get("name"), "file_path": file_path},
                            config, http_client,
                        ))

            if (
                progress_interval
                and run.turns_used > 0
                and run.turns_used % progress_interval == 0
                and run.turns_used != last_webhook_turn
            ):
                last_webhook_turn = run.turns_used
                await _fire_progress_webhook(run, config, http_client)

        if proc.returncode is None:
            await proc.wait()

        if run._cancel_event.is_set():
            run.status = "cancelled"
            run.phase = "complete"
            run.completed_at = _now()
            run.add_activity({"type": "result", "subtype": "cancelled", "detail": "Task cancelled"})
        elif run.status == "running":
            # No result event received — check exit code
            if proc.returncode == 0:
                run.status = "completed"
                run.phase = "complete"
                run.completed_at = _now()
                run.add_activity({"type": "result", "subtype": "success", "detail": "Task completed"})
                if run.execution_mode == "plan" and not run.plan_text:
                    run.plan_text = run.result_summary or ""
                    run.plan_status = "pending_review"
            else:
                stderr_out = await proc.stderr.read() if proc.stderr else b""
                error_detail = stderr_out.decode().strip() or f"claude exited with code {proc.returncode}"
                run.status = "failed"
                run.phase = "complete"
                run.completed_at = _now()
                run.result_summary = error_detail[:500]
                run.add_activity({"type": "result", "subtype": "error", "detail": error_detail[:300]})

    except asyncio.CancelledError:
        if run._process and run._process.returncode is None:
            run._process.terminate()
            await run._process.wait()
        run.status = "cancelled"
        run.phase = "complete"
        run.completed_at = _now()
        run.add_activity({"type": "result", "subtype": "cancelled", "detail": "Task cancelled"})
    except Exception as e:
        run.status = "failed"
        run.phase = "complete"
        run.completed_at = _now()
        run.result_summary = str(e)
        run.add_activity({"type": "result", "subtype": "error", "detail": str(e)})
        logger.exception("Task %s failed", run.run_id)
    finally:
        run._process = None
        run.task = None
        try:
            await _fire_webhook(run, config, http_client)
        except Exception:
            logger.exception("Webhook fire failed for run %s during cleanup", run.run_id)


# ---------------------------------------------------------------------------
# OpenCode runner
# ---------------------------------------------------------------------------


def _handle_opencode_event(run: RunState, event: dict) -> None:
    event_type = event.get("type", "")

    if event_type == "step_start":
        run.phase = "thinking"
        run.turns_used += 1
        if event.get("model"):
            run.model = event["model"]
        run.add_activity({"type": "step_start", "detail": "New reasoning step"})

    elif event_type == "text":
        text = event.get("text", "").strip()
        if text:
            run.result_summary = text[:200]
            run.add_activity({"type": "text", "detail": text[:300]})
            # Accumulate text for plan mode
            if run.execution_mode == "plan":
                run.plan_text = (run.plan_text or "") + text + "\n"

    elif event_type == "tool_use":
        tool_name = event.get("tool", event.get("name", "unknown"))
        status = event.get("status", "")
        run.current_tool = tool_name
        run.phase = "using_tool"

        tool_input = event.get("input", {})
        if isinstance(tool_input, dict):
            file_path = tool_input.get("file_path") or tool_input.get("file") or tool_input.get("path")
        else:
            file_path = None

        if file_path and tool_name.lower() in ("write", "edit", "patch"):
            run.files_modified.add(file_path)
            run.current_file = file_path
            run.phase = "editing_files"

        if status == "completed":
            run.add_activity({
                "type": "tool_end",
                "tool": tool_name,
                "detail": f"Finished {tool_name}",
            })
            run.current_tool = None
            run.current_file = None
            run.phase = "thinking"
        else:
            run.add_activity({
                "type": "tool_start",
                "tool": tool_name,
                "input": {k: v for k, v in tool_input.items() if k != "content"} if isinstance(tool_input, dict) else {},
            })

    elif event_type == "step_finish":
        tokens = event.get("tokens", {})
        if isinstance(tokens, dict):
            run.input_tokens += tokens.get("input", 0)
            run.output_tokens += tokens.get("output", 0)
            run.tokens_used = run.input_tokens + run.output_tokens
        reason = event.get("reason", "")
        if reason == "stop":
            run.add_activity({"type": "step_finish", "detail": "Step finished (stop)"})


async def run_opencode_task(
    run: RunState,
    task_description: str,
    config: dict,
    http_client: httpx.AsyncClient,
    system_prompt: str | None = None,
    model_override: str | None = None,
) -> None:
    opencode_config = config.get("opencode", {})
    model = model_override or opencode_config.get("model", "")
    progress_interval = config.get("webhook_progress_interval", 10)

    run.model = model or "opencode/default"
    run.status = "running"
    run.phase = "thinking"
    run.started_at = _now()
    run.add_activity({"type": "start", "detail": f"Task execution started (opencode, model={run.model})"})

    # Plan mode: prepend planning constraint to the prompt
    if run.execution_mode == "plan":
        task_description = _PLAN_ONLY_PREFIX + "\n\n" + task_description

    # Prepend system prompt to task if provided (opencode has no --system-prompt flag)
    full_task = task_description
    if system_prompt:
        full_task = f"{system_prompt}\n\n{task_description}"

    cmd: list[str] = ["opencode", "run", "--format", "json"]
    if model:
        cmd.extend(["--model", model])
    cmd.append(full_task)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=run.repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_subprocess_env(config),
            limit=_SUBPROCESS_STREAM_LIMIT,
        )
        run._process = proc

        assert proc.stdout is not None
        last_webhook_turn = 0
        while True:
            if run._cancel_event.is_set():
                if proc.returncode is None:
                    proc.terminate()
                    await proc.wait()
                break

            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            if not line:
                break

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            _handle_opencode_event(run, event)

            # Fire per-event webhooks for tool use and step events (fire-and-forget)
            event_type = event.get("type", "")
            if event_type == "tool_use":
                tool_input = event.get("input", {})
                file_path = None
                if isinstance(tool_input, dict):
                    file_path = tool_input.get("file_path") or tool_input.get("file") or tool_input.get("path")
                asyncio.create_task(_fire_event_webhook(
                    run, "tool_use",
                    {"tool_name": event.get("tool", event.get("name")), "file_path": file_path},
                    config, http_client,
                ))
            elif event_type in ("step_start", "step_finish"):
                asyncio.create_task(_fire_event_webhook(
                    run, event_type, {}, config, http_client,
                ))

            # Fire progress webhook every N turns (only once per threshold)
            if (
                progress_interval
                and run.turns_used > 0
                and run.turns_used % progress_interval == 0
                and run.turns_used != last_webhook_turn
            ):
                last_webhook_turn = run.turns_used
                await _fire_progress_webhook(run, config, http_client)

        if proc.returncode is None:
            await proc.wait()

        if run._cancel_event.is_set():
            run.status = "cancelled"
            run.phase = "complete"
            run.completed_at = _now()
            run.add_activity({"type": "result", "subtype": "cancelled", "detail": "Task cancelled"})
        elif proc.returncode == 0:
            run.status = "completed"
            run.phase = "complete"
            run.completed_at = _now()
            run.add_activity({"type": "result", "subtype": "success", "detail": "Task completed"})
            if run.execution_mode == "plan":
                if not run.plan_text:
                    run.plan_text = run.result_summary or ""
                run.plan_status = "pending_review"
        else:
            stderr_out = await proc.stderr.read() if proc.stderr else b""
            error_detail = stderr_out.decode().strip() or f"opencode exited with code {proc.returncode}"
            run.status = "failed"
            run.phase = "complete"
            run.completed_at = _now()
            run.result_summary = error_detail[:500]
            run.add_activity({"type": "result", "subtype": "error", "detail": error_detail[:300]})

    except asyncio.CancelledError:
        if run._process and run._process.returncode is None:
            run._process.terminate()
            await run._process.wait()
        run.status = "cancelled"
        run.phase = "complete"
        run.completed_at = _now()
        run.add_activity({"type": "result", "subtype": "cancelled", "detail": "Task cancelled"})
    except Exception as e:
        run.status = "failed"
        run.phase = "complete"
        run.completed_at = _now()
        run.result_summary = str(e)
        run.add_activity({"type": "result", "subtype": "error", "detail": str(e)})
        logger.exception("OpenCode task %s failed", run.run_id)
    finally:
        run._process = None
        run.task = None
        try:
            await _fire_webhook(run, config, http_client)
        except Exception:
            logger.exception("Webhook fire failed for run %s during cleanup", run.run_id)


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


def _build_webhook_headers(config: dict) -> dict[str, str]:
    headers: dict[str, str] = {}
    bearer_token = config.get("webhook_bearer_token")
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers


async def _fire_webhook(
    run: RunState,
    config: dict,
    http_client: httpx.AsyncClient,
) -> None:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return

    payload = {
        "run_id": run.run_id,
        "type": "completion",
        "status": run.status,
        "summary": run.result_summary,
        "files_modified": sorted(run.files_modified),
        "turns_used": run.turns_used,
        "cost_usd": run.cost_usd,
        "duration_seconds": round(
            (datetime.fromisoformat(run.completed_at) - datetime.fromisoformat(run.started_at)).total_seconds(), 1
        ) if run.completed_at and run.started_at else 0,
        "recent_activity": run.activity_log[-10:],
    }

    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    headers = _build_webhook_headers(config)

    try:
        resp = await http_client.post(webhook_url, content=payload_bytes, headers={
            "Content-Type": "application/json",
            **headers,
        }, timeout=10)
        logger.info("Webhook sent for run %s — status %d", run.run_id, resp.status_code)
    except Exception:
        logger.exception("Webhook failed for run %s", run.run_id)


async def _fire_event_webhook(
    run: RunState,
    event_name: str,
    details: dict,
    config: dict,
    http_client: httpx.AsyncClient,
) -> None:
    """Send a lightweight per-event webhook (tool use, step start/finish)."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return

    payload = {
        "run_id": run.run_id,
        "type": "hook",
        "event": event_name,
        "tool_name": details.get("tool_name"),
        "file_path": details.get("file_path"),
        "ts": _now(),
    }

    headers = _build_webhook_headers(config)
    try:
        await http_client.post(webhook_url, json=payload, headers={
            "Content-Type": "application/json",
            **headers,
        }, timeout=5)
    except Exception:
        pass  # best-effort, don't block the event loop


async def _fire_progress_webhook(
    run: RunState,
    config: dict,
    http_client: httpx.AsyncClient,
) -> None:
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return

    payload = {
        "run_id": run.run_id,
        "type": "progress",
        "status": run.status,
        "phase": run.phase,
        "turns_used": run.turns_used,
        "turns_max": run.turns_max,
        "cost_usd": run.cost_usd,
        "files_modified": sorted(run.files_modified),
        "summary_so_far": run.result_summary,
        "recent_activity": run.activity_log[-5:],
    }

    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    headers = _build_webhook_headers(config)

    try:
        await http_client.post(webhook_url, content=payload_bytes, headers={
            "Content-Type": "application/json",
            **headers,
        }, timeout=10)
    except Exception:
        logger.warning("Progress webhook failed for run %s", run.run_id)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(server: FastMCP):
    config = load_config()
    workspace_dir = config.get("workspace_dir", "/workspaces")
    os.makedirs(workspace_dir, exist_ok=True)

    max_concurrent_clones = config.get("max_concurrent_clones", 3)
    clone_semaphore = asyncio.Semaphore(max_concurrent_clones)

    runs: dict[str, RunState] = {}

    async with httpx.AsyncClient() as http_client:
        logger.info("poke-code started")
        try:
            yield {
                "config": config,
                "runs": runs,
                "http_client": http_client,
                "clone_semaphore": clone_semaphore,
                "auth_flows": _auth_flows,
            }
        finally:
            for run in runs.values():
                if run.task and not run.task.done():
                    run.task.cancel()
            pending = [r.task for r in runs.values() if r.task and not r.task.done()]
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            logger.info("poke-code shut down")


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp_api_key = os.environ.get("MCP_API_KEY", "")

# Refuse to start unauthenticated in production
if not mcp_api_key and os.environ.get("ENVIRONMENT") == "production":
    raise SystemExit("MCP_API_KEY is required in production. Set the MCP_API_KEY env var.")

auth = ApiKeyAuth(mcp_api_key) if mcp_api_key else None
if not mcp_api_key:
    logger.warning("MCP_API_KEY not set — server is unauthenticated.")

mcp = FastMCP("poke-code", lifespan=lifespan, auth=auth)


@mcp.custom_route("/mcp", methods=["GET"])
async def health(request):
    from starlette.responses import JSONResponse
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Auth key entry routes (browser-based, no API key passes through MCP)
# ---------------------------------------------------------------------------

_AUTH_FORM_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>poke-code — {provider} auth</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:system-ui,sans-serif;background:#0a0a0a;color:#e5e5e5;display:flex;justify-content:center;align-items:center;min-height:100vh}}
  .card{{background:#171717;border:1px solid #262626;border-radius:12px;padding:2rem;max-width:420px;width:100%}}
  h1{{font-size:1.25rem;margin-bottom:.5rem}}
  p{{font-size:.875rem;color:#a3a3a3;margin-bottom:1.5rem}}
  label{{font-size:.875rem;display:block;margin-bottom:.5rem}}
  input[type=password]{{width:100%;padding:.625rem;background:#0a0a0a;border:1px solid #404040;border-radius:6px;color:#e5e5e5;font-size:.875rem;margin-bottom:1rem}}
  input[type=password]:focus{{outline:none;border-color:#3b82f6}}
  button{{width:100%;padding:.625rem;background:#3b82f6;color:#fff;border:none;border-radius:6px;font-size:.875rem;cursor:pointer}}
  button:hover{{background:#2563eb}}
  .ok{{text-align:center;color:#22c55e;font-size:1.1rem;padding:2rem 0}}
  .err{{color:#ef4444;font-size:.875rem;margin-bottom:1rem}}
</style></head><body>
<div class="card">
  {body}
</div></body></html>"""

_AUTH_FORM_BODY = """<h1>Authenticate {provider}</h1>
<p>Enter your API key below. It will be stored on the server — the MCP client never sees it.</p>
{error}
<form method="POST">
  <label for="key">API Key</label>
  <input type="password" id="key" name="key" placeholder="sk-..." required autofocus>
  <button type="submit">Save &amp; authenticate</button>
</form>"""

_AUTH_SUCCESS_BODY = """<div class="ok">&#10003; {provider} authenticated</div>
<p style="text-align:center;margin-top:1rem">You can close this tab.</p>"""

_AUTH_EXPIRED_BODY = """<div class="ok" style="color:#ef4444">This link has expired.</div>
<p style="text-align:center;margin-top:1rem">Request a new one via provider_login.</p>"""


@mcp.custom_route("/auth/{token}", methods=["GET"])
async def auth_form_get(request):
    from starlette.responses import HTMLResponse
    token = request.path_params["token"]
    _expire_auth_flows(_auth_flows)
    flow = _auth_flows.get(token)
    if not flow or flow.get("type") != "api_key_form":
        return HTMLResponse(
            _AUTH_FORM_HTML.format(provider="", body=_AUTH_EXPIRED_BODY), status_code=410
        )
    provider = flow["provider"]
    body = _AUTH_FORM_BODY.format(provider=provider, error="")
    return HTMLResponse(_AUTH_FORM_HTML.format(provider=provider, body=body))


@mcp.custom_route("/auth/{token}", methods=["POST"])
async def auth_form_post(request):
    from starlette.responses import HTMLResponse
    token = request.path_params["token"]
    _expire_auth_flows(_auth_flows)
    flow = _auth_flows.get(token)
    if not flow or flow.get("type") != "api_key_form":
        return HTMLResponse(
            _AUTH_FORM_HTML.format(provider="", body=_AUTH_EXPIRED_BODY), status_code=410
        )
    form = await request.form()
    key = (form.get("key") or "").strip()
    provider = flow["provider"]
    auth_key = flow["auth_key"]
    if not key:
        error = '<p class="err">API key cannot be empty.</p>'
        body = _AUTH_FORM_BODY.format(provider=provider, error=error)
        return HTMLResponse(_AUTH_FORM_HTML.format(provider=provider, body=body), status_code=400)
    _write_auth_json({auth_key: {"type": "api", "key": key}})
    flow["completed"] = True
    body = _AUTH_SUCCESS_BODY.format(provider=provider)
    return HTMLResponse(_AUTH_FORM_HTML.format(provider=provider, body=body))


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(description="Clone a git repository and prepare a workspace for task execution.")
async def clone_and_init(
    ctx: Context,
    repo_url: str,
    branch: str = "main",
) -> dict:
    config: dict = ctx.request_context.lifespan_context["config"]
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    clone_semaphore: asyncio.Semaphore = ctx.request_context.lifespan_context["clone_semaphore"]
    workspace_dir = config.get("workspace_dir", "/workspaces")

    if not _SAFE_REPO_URL.match(repo_url):
        return {"error": "Invalid repo_url: only HTTPS git URLs are allowed", "status": "failed"}

    if branch.startswith("-") or not re.match(r"^[a-zA-Z0-9._\-/]+$", branch):
        return {"error": "Invalid branch name", "status": "failed"}

    run_id = str(uuid.uuid4())
    repo_path = os.path.join(workspace_dir, run_id)

    async with clone_semaphore:
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--branch", branch, "--single-branch", "--depth", "1",
                repo_url, repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                shutil.rmtree(repo_path, ignore_errors=True)
                return {"error": "git clone timed out after 120 seconds", "status": "failed"}
            if proc.returncode != 0:
                shutil.rmtree(repo_path, ignore_errors=True)
                return {"error": f"git clone failed: {stderr.decode().strip()}", "status": "failed"}
        except Exception as e:
            shutil.rmtree(repo_path, ignore_errors=True)
            return {"error": f"git clone failed: {e}", "status": "failed"}

    run = RunState(run_id=run_id, repo_url=repo_url, repo_path=repo_path)
    runs[run_id] = run

    # LRU eviction
    non_running = [r for r in runs.values() if r.status != "running"]
    if len(non_running) > MAX_COMPLETED_RUNS:
        oldest = min(non_running, key=lambda r: r.created_at)
        shutil.rmtree(oldest.repo_path, ignore_errors=True)
        del runs[oldest.run_id]

    return {"run_id": run_id, "repo_path": repo_path, "status": "ready"}


@mcp.tool(description="Execute a coding task in a previously cloned workspace. Supports three modes: 'plan' (analyze and produce a plan without modifying files), 'implement' (execute a previously approved plan), and 'full' (default, immediate execution). For plan→implement workflow: call with mode='plan', review via get_status, approve with approve_plan, then call with mode='implement'.")
async def execute_task(
    ctx: Context,
    run_id: str,
    task_description: str,
    system_prompt: str = "",
    claude_md: str = "",
    engine: str = "",
    model: str = "",
    mode: str = "full",
) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    config: dict = ctx.request_context.lifespan_context["config"]
    http_client: httpx.AsyncClient = ctx.request_context.lifespan_context["http_client"]

    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found", "status": "failed"}
    if run.status not in ("ready", "completed", "failed"):
        return {"error": f"Run {run_id} is currently {run.status}", "status": "failed"}

    # Validate mode
    if mode not in ("plan", "implement", "full"):
        return {"error": f"Invalid mode '{mode}'. Must be 'plan', 'implement', or 'full'.", "status": "failed"}

    # Implement mode requires an approved plan
    if mode == "implement":
        if run.plan_status != "approved" or run.plan_text is None:
            return {"error": "Cannot implement: no approved plan. Run with mode='plan' first, then approve_plan.", "status": "failed"}

    # Resolve engine
    resolved_engine = engine or config.get("default_engine", "claude")
    if resolved_engine not in ("claude", "opencode"):
        return {"error": f"Invalid engine '{resolved_engine}'. Must be 'claude' or 'opencode'.", "status": "failed"}

    if not shutil.which(resolved_engine if resolved_engine == "opencode" else "claude"):
        return {"error": f"{resolved_engine} CLI is not installed or not on PATH", "status": "failed"}

    # Per-engine concurrency check
    engine_config_key = resolved_engine
    max_concurrent = config.get(engine_config_key, {}).get("max_concurrent_tasks", 3)
    active_count = sum(1 for r in runs.values() if r.status == "running" and r.engine == resolved_engine)
    if active_count >= max_concurrent:
        return {"error": f"Concurrency limit reached for {resolved_engine} ({max_concurrent} tasks running)", "status": "failed"}

    # Write CLAUDE.md if provided
    if claude_md:
        claude_md_path = os.path.join(run.repo_path, "CLAUDE.md")
        with open(claude_md_path, "w") as f:
            f.write(claude_md)

    # Append Context7 prompt when API key is available
    context7_key = config.get("context7_api_key") or os.environ.get("CONTEXT7_API_KEY", "")
    if context7_key:
        system_prompt = (system_prompt + "\n\n" + _CONTEXT7_PROMPT) if system_prompt else _CONTEXT7_PROMPT

    # Write engine-specific settings (hooks, MCP config)
    if resolved_engine == "claude":
        _write_claude_settings(run.repo_path, run_id, config)
    elif resolved_engine == "opencode":
        _write_opencode_config(run.repo_path, config)

    # Preserve plan_text for implement mode before reset
    saved_plan = run.plan_text if mode == "implement" else None

    # Reset run state for (re-)execution
    run.status = "running"
    run.phase = "thinking"
    run.engine = resolved_engine
    run.model = model or ""
    run.execution_mode = mode
    run.activity_log.clear()
    run.files_modified.clear()
    run.current_tool = None
    run.current_file = None
    run.turns_used = 0
    run.cost_usd = 0.0
    run.tokens_used = 0
    run.input_tokens = 0
    run.output_tokens = 0
    run.started_at = None
    run.completed_at = None
    run.result_summary = None
    run._next_seq = 0
    run._cancel_event.clear()
    run._process = None

    # Handle plan fields based on mode
    if mode == "implement":
        run.plan_text = saved_plan
    elif mode == "plan":
        run.plan_text = None
        run.plan_status = None
    else:
        # mode="full" — clear stale plan fields
        run.plan_text = None
        run.plan_status = None

    # Wrap task with approved plan context for implement mode
    if mode == "implement" and saved_plan:
        task_description = f"## Approved Plan\n\n{saved_plan}\n\n## Task\n\n{task_description}\n\nImplement the approved plan above."

    if resolved_engine == "opencode":
        run.task = asyncio.create_task(
            run_opencode_task(
                run, task_description, config, http_client,
                system_prompt=system_prompt or None,
                model_override=model or None,
            )
        )
    else:
        run.task = asyncio.create_task(
            run_claude_task(
                run, task_description, config, http_client,
                system_prompt=system_prompt or None,
                model_override=model or None,
            )
        )

    return {"run_id": run_id, "status": "running", "engine": resolved_engine, "model": model or None}


@mcp.tool(description="Get detailed status of a run including current tool, files modified, cost, and recent activity.")
async def get_status(ctx: Context, run_id: str) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found"}
    return run.to_status_dict()


@mcp.tool(description="Get the full activity log for a run, paginated from a sequence offset.")
async def get_output(ctx: Context, run_id: str, after_seq: int = -1) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found"}

    entries = [e for e in run.activity_log if e.get("seq", 0) > after_seq]
    next_seq = entries[-1]["seq"] if entries else after_seq
    return {
        "entries": entries,
        "next_seq": next_seq,
        "has_more": False,
    }


@mcp.tool(description="List all runs with summary info.")
async def list_runs(ctx: Context) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    return {"runs": [r.to_summary_dict() for r in runs.values()]}


@mcp.tool(description="Cancel a running task.")
async def cancel_task(ctx: Context, run_id: str) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found"}
    if run.status != "running" or not run.task:
        return {"error": f"Run {run_id} is not running", "status": run.status}

    run._cancel_event.set()
    if run._process and run._process.returncode is None:
        run._process.terminate()
    run.task.cancel()
    return {"run_id": run_id, "status": "cancelling"}


@mcp.tool(description="Remove a run's workspace directory and delete the run. Only works on non-running runs.")
async def cleanup_run(ctx: Context, run_id: str) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found"}
    if run.status == "running":
        return {"error": f"Run {run_id} is currently running — cancel it first"}

    shutil.rmtree(run.repo_path, ignore_errors=True)
    del runs[run_id]
    return {"run_id": run_id, "status": "cleaned"}


@mcp.tool(description="Get git diff of changes made in a run's workspace. Shows what the agent modified.")
async def get_diff(ctx: Context, run_id: str) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found"}

    try:
        # Get full diff including untracked files
        proc = await asyncio.create_subprocess_exec(
            "git", "diff", "HEAD",
            cwd=run.repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        diff_out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

        # Get diff stats
        proc2 = await asyncio.create_subprocess_exec(
            "git", "diff", "HEAD", "--stat",
            cwd=run.repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stat_out, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)

        # List untracked files
        proc3 = await asyncio.create_subprocess_exec(
            "git", "ls-files", "--others", "--exclude-standard",
            cwd=run.repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        untracked_out, _ = await asyncio.wait_for(proc3.communicate(), timeout=30)

        diff_text = diff_out.decode()
        untracked = [f for f in untracked_out.decode().strip().split("\n") if f]

        return {
            "run_id": run_id,
            "diff": diff_text,
            "stat": stat_out.decode().strip(),
            "untracked_files": untracked,
            "files_modified": sorted(run.files_modified),
        }
    except asyncio.TimeoutError:
        return {"error": "git diff timed out", "status": "failed"}
    except Exception as e:
        return {"error": f"git diff failed: {e}", "status": "failed"}


@mcp.tool(description="Commit and push changes in a run's workspace. Run must not be currently executing.")
async def commit_and_push(
    ctx: Context,
    run_id: str,
    commit_message: str,
    branch: str = "",
) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found"}
    if run.status == "running":
        return {"error": f"Run {run_id} is still running"}

    # Validate branch name if provided
    if branch and (branch.startswith("-") or not re.match(r"^[a-zA-Z0-9._\-/]+$", branch)):
        return {"error": "Invalid branch name", "status": "failed"}

    cwd = run.repo_path

    try:
        # Optionally create and switch to new branch
        if branch:
            proc = await asyncio.create_subprocess_exec(
                "git", "checkout", "-b", branch,
                cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            _, err = await asyncio.wait_for(proc.communicate(), timeout=30)
            if proc.returncode != 0:
                return {"error": f"git checkout -b failed: {err.decode().strip()}", "status": "failed"}

        # Stage all changes
        proc = await asyncio.create_subprocess_exec(
            "git", "add", "-A",
            cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)

        # Commit
        proc = await asyncio.create_subprocess_exec(
            "git", "commit", "-m", commit_message,
            cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode != 0:
            err_text = err.decode().strip()
            if "nothing to commit" in err_text:
                return {"error": "Nothing to commit", "status": "failed"}
            return {"error": f"git commit failed: {err_text}", "status": "failed"}

        # Get commit SHA
        proc = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "HEAD",
            cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        sha_out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        commit_sha = sha_out.decode().strip()

        # Push
        proc = await asyncio.create_subprocess_exec(
            "git", "push", "--set-upstream", "origin", "HEAD",
            cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        _, err = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            return {
                "commit_sha": commit_sha,
                "status": "committed_not_pushed",
                "error": f"git push failed: {err.decode().strip()}",
            }

        # Get current branch name
        proc = await asyncio.create_subprocess_exec(
            "git", "rev-parse", "--abbrev-ref", "HEAD",
            cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        branch_out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

        return {
            "run_id": run_id,
            "commit_sha": commit_sha,
            "branch": branch_out.decode().strip(),
            "status": "pushed",
        }
    except asyncio.TimeoutError:
        return {"error": "git operation timed out", "status": "failed"}
    except Exception as e:
        return {"error": f"git operation failed: {e}", "status": "failed"}


@mcp.tool(description="Approve or reject a plan from execute_task(mode='plan'). After approval, call execute_task(mode='implement') to execute.")
async def approve_plan(
    ctx: Context,
    run_id: str,
    approve: bool = True,
    feedback: str = "",
) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    run = runs.get(run_id)
    if not run:
        return {"error": f"Run {run_id} not found", "status": "failed"}
    if run.plan_status != "pending_review":
        return {"error": f"No plan pending review (plan_status={run.plan_status})", "status": "failed"}

    if approve:
        run.plan_status = "approved"
        run.add_activity({"type": "plan", "detail": "Plan approved"})
        return {"run_id": run_id, "status": "approved", "plan_text": run.plan_text}
    else:
        run.plan_status = "rejected"
        run.status = "ready"
        if feedback:
            run.add_activity({"type": "plan", "detail": f"Plan rejected: {feedback}"})
        else:
            run.add_activity({"type": "plan", "detail": "Plan rejected"})
        return {"run_id": run_id, "status": "rejected"}


@mcp.tool(description="Check if Claude Code authentication is configured. Call this before execute_task with the claude engine to verify auth. Returns setup instructions if not configured.")
async def setup_auth(ctx: Context, engine: str = "claude") -> dict:
    if engine == "claude":
        has_oauth_token = bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))
        has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
        has_credentials_file = os.path.isfile(os.path.expanduser("~/.claude/.credentials.json"))

        if has_oauth_token or has_api_key or has_credentials_file:
            method = "oauth_token" if has_oauth_token else "api_key" if has_api_key else "credentials_file"
            return {"authenticated": True, "engine": "claude", "method": method}

        return {
            "authenticated": False,
            "engine": "claude",
            "instructions": (
                "Claude Code is not authenticated. "
                "Tell the user to do ONE of the following:\n\n"
                "Option 1 (recommended — uses existing Claude subscription):\n"
                "  1. Run `claude setup-token` on a machine with a browser\n"
                "  2. Set the output as CLAUDE_CODE_OAUTH_TOKEN env var on this server\n\n"
                "Option 2 (API key — pay-per-use):\n"
                "  1. Get an API key from console.anthropic.com\n"
                "  2. Set it as ANTHROPIC_API_KEY env var on this server"
            ),
        }

    elif engine == "opencode":
        if not shutil.which("opencode"):
            return {"authenticated": False, "engine": "opencode", "instructions": "opencode CLI is not installed."}

        auth_data = _read_auth_json()
        authenticated = []
        not_authenticated = []

        for provider, info in _OPENCODE_PROVIDERS.items():
            auth_key = info.get("auth_key", provider)
            ptype = info["type"]

            # Check auth.json
            cred = auth_data.get(auth_key)
            if cred:
                cred_type = cred.get("type", "unknown")
                expires = cred.get("expires", 0)
                status = "active"
                if expires and expires < time.time() * 1000:  # auth.json uses ms
                    status = "expired"
                authenticated.append({"provider": provider, "method": cred_type, "status": status})
                continue

            # Check env vars
            env_keys = info.get("env")
            if env_keys:
                keys = [env_keys] if isinstance(env_keys, str) else env_keys
                if all(os.environ.get(k) for k in keys):
                    authenticated.append({"provider": provider, "method": "env", "status": "active"})
                    continue

            # Not authenticated — list available auth methods
            auth_methods = []
            if ptype == "api":
                auth_methods.append("api_key")
            elif ptype == "oauth_device":
                auth_methods.extend(["oauth_device", "api_key"])
            elif ptype == "oauth_redirect":
                auth_methods.extend(["oauth_redirect", "api_key"])
            elif ptype == "env_only":
                auth_methods.append("env_vars")
            not_authenticated.append({"provider": provider, "auth_methods": auth_methods})

        return {
            "engine": "opencode",
            "binary_found": True,
            "authenticated": authenticated,
            "not_authenticated": not_authenticated,
        }

    return {"error": f"Unknown engine '{engine}'"}


def _expire_auth_flows(auth_flows: dict[str, dict]) -> None:
    """Remove expired auth flows from the in-memory store."""
    now = time.time()
    expired = [fid for fid, f in auth_flows.items() if f.get("expires_at", 0) < now]
    for fid in expired:
        del auth_flows[fid]


@mcp.tool(description=(
    "Authenticate an OpenCode provider. "
    "For API key providers: returns a URL where the user enters their key directly (the MCP client never sees the key). "
    "For OAuth providers (openai, anthropic, google): starts an OAuth flow. "
    "Returns a flow_id + instructions — poll with provider_login_poll."
))
async def provider_login(
    ctx: Context,
    provider: str,
    plan: str = "console",
) -> dict:
    auth_flows: dict[str, dict] = ctx.request_context.lifespan_context["auth_flows"]
    http_client: httpx.AsyncClient = ctx.request_context.lifespan_context["http_client"]

    _expire_auth_flows(auth_flows)

    if provider not in _OPENCODE_PROVIDERS:
        return {"error": f"Unknown provider '{provider}'. Known: {', '.join(_OPENCODE_PROVIDERS)}"}

    info = _OPENCODE_PROVIDERS[provider]
    ptype = info["type"]
    auth_key = info.get("auth_key", provider)

    # --- Env-only providers ---
    if ptype == "env_only":
        env_keys = info["env"]
        keys = [env_keys] if isinstance(env_keys, str) else env_keys
        missing = [k for k in keys if not os.environ.get(k)]
        if missing:
            return {"error": f"Set these env vars on the server: {', '.join(missing)}", "provider": provider}
        return {"status": "authenticated", "provider": provider, "method": "env"}

    # --- API key providers — serve a browser form ---
    if ptype == "api":
        flow_id = str(uuid.uuid4())
        auth_flows[flow_id] = {
            "provider": provider,
            "auth_key": auth_key,
            "type": "api_key_form",
            "completed": False,
            "expires_at": time.time() + _API_KEY_FLOW_TTL,
        }
        return {
            "status": "awaiting_auth",
            "flow_id": flow_id,
            "url": f"/auth/{flow_id}",
            "expires_in": _API_KEY_FLOW_TTL,
            "instructions": f"Open the URL to enter your {provider} API key. The key is submitted directly to the server — this client never sees it.",
        }

    # --- OpenAI device code flow ---
    if provider == "openai":
        try:
            resp = await http_client.post(
                _OPENAI_DEVICE_AUTH_URL,
                data={
                    "client_id": _OPENAI_CLIENT_ID,
                    "scope": "openid profile email offline_access",
                    "audience": "https://api.openai.com/v1",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            if resp.status_code != 200:
                return {"error": f"OpenAI device auth failed: {resp.status_code} {resp.text}"}
            body = resp.json()
        except Exception as e:
            return {"error": f"Failed to contact OpenAI auth: {e}"}

        flow_id = str(uuid.uuid4())
        auth_flows[flow_id] = {
            "provider": "openai",
            "type": "device_code",
            "device_code": body.get("device_code"),
            "interval": body.get("interval", 5),
            "expires_at": time.time() + body.get("expires_in", _DEVICE_FLOW_TTL),
        }
        return {
            "status": "awaiting_auth",
            "flow_id": flow_id,
            "url": body.get("verification_uri_complete") or body.get("verification_uri", "https://auth.openai.com/activate"),
            "code": body.get("user_code", ""),
            "expires_in": body.get("expires_in", _DEVICE_FLOW_TTL),
            "instructions": "Open the URL and enter the code to authenticate.",
        }

    # --- GitHub Copilot device code flow ---
    if provider == "github-copilot":
        try:
            resp = await http_client.post(
                "https://github.com/login/device/code",
                data={"client_id": "Iv1.b507a08c87ecfe98", "scope": "read:user"},
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if resp.status_code != 200:
                return {"error": f"GitHub device auth failed: {resp.status_code} {resp.text}"}
            body = resp.json()
        except Exception as e:
            return {"error": f"Failed to contact GitHub auth: {e}"}

        flow_id = str(uuid.uuid4())
        auth_flows[flow_id] = {
            "provider": "github-copilot",
            "type": "device_code",
            "device_code": body.get("device_code"),
            "interval": body.get("interval", 5),
            "expires_at": time.time() + body.get("expires_in", _DEVICE_FLOW_TTL),
        }
        return {
            "status": "awaiting_auth",
            "flow_id": flow_id,
            "url": body.get("verification_uri", "https://github.com/login/device"),
            "code": body.get("user_code", ""),
            "expires_in": body.get("expires_in", _DEVICE_FLOW_TTL),
            "instructions": "Open the URL and enter the code to authenticate with GitHub.",
        }

    # --- Anthropic redirect flow ---
    if provider == "anthropic":
        if plan not in ("max", "console"):
            return {"error": "plan must be 'max' or 'console'"}

        verifier, challenge = _generate_pkce()
        state = str(uuid.uuid4())
        flow_id = str(uuid.uuid4())
        redirect_uri = "http://localhost:0/callback"  # placeholder — user provides via callback tool

        auth_url = _ANTHROPIC_AUTHORIZE_URLS[plan]
        params = (
            f"?response_type=code"
            f"&client_id={_ANTHROPIC_CLIENT_ID}"
            f"&redirect_uri={redirect_uri}"
            f"&scope=org:read user:read"
            f"&state={state}"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
        )

        auth_flows[flow_id] = {
            "provider": "anthropic",
            "type": "redirect",
            "verifier": verifier,
            "state": state,
            "redirect_uri": redirect_uri,
            "token_url": _ANTHROPIC_TOKEN_URL,
            "plan": plan,
            "expires_at": time.time() + _REDIRECT_FLOW_TTL,
            "completed": False,
        }
        return {
            "status": "awaiting_auth",
            "flow_id": flow_id,
            "url": auth_url + params,
            "expires_in": _REDIRECT_FLOW_TTL,
            "instructions": "Open this URL in a browser to authenticate. Then use provider_login_callback with the redirect URL.",
        }

    # --- Google redirect flow ---
    if provider == "google":
        verifier, challenge = _generate_pkce()
        state = str(uuid.uuid4())
        flow_id = str(uuid.uuid4())
        redirect_uri = "http://localhost:8085/oauth2callback"

        params = (
            f"?response_type=code"
            f"&client_id={_GOOGLE_CLIENT_ID}"
            f"&redirect_uri={redirect_uri}"
            f"&scope=https://www.googleapis.com/auth/generative-language.retriever"
            f"&state={state}"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
            f"&access_type=offline"
            f"&prompt=consent"
        )

        auth_flows[flow_id] = {
            "provider": "google",
            "type": "redirect",
            "verifier": verifier,
            "state": state,
            "redirect_uri": redirect_uri,
            "token_url": _GOOGLE_TOKEN_URL,
            "expires_at": time.time() + _REDIRECT_FLOW_TTL,
            "completed": False,
        }
        return {
            "status": "awaiting_auth",
            "flow_id": flow_id,
            "url": _GOOGLE_AUTH_URL + params,
            "expires_in": _REDIRECT_FLOW_TTL,
            "instructions": "Open this URL in a browser to authenticate. Then use provider_login_callback with the redirect URL.",
        }

    return {"error": f"Provider '{provider}' does not support interactive login."}


@mcp.tool(description="Poll an in-progress auth flow. Call after provider_login returned status='awaiting_auth'.")
async def provider_login_poll(ctx: Context, flow_id: str) -> dict:
    auth_flows: dict[str, dict] = ctx.request_context.lifespan_context["auth_flows"]
    http_client: httpx.AsyncClient = ctx.request_context.lifespan_context["http_client"]

    _expire_auth_flows(auth_flows)

    flow = auth_flows.get(flow_id)
    if not flow:
        return {"error": f"Flow {flow_id} not found or expired."}

    if flow.get("expires_at", 0) < time.time():
        del auth_flows[flow_id]
        return {"status": "expired", "flow_id": flow_id}

    # --- API key form: check if user submitted via browser ---
    if flow["type"] == "api_key_form":
        if flow.get("completed"):
            del auth_flows[flow_id]
            return {"status": "authenticated", "provider": flow["provider"]}
        return {"status": "pending", "flow_id": flow_id, "instructions": "Waiting for the user to enter their API key in the browser."}

    # --- Redirect flows: check if completed by callback ---
    if flow["type"] == "redirect":
        if flow.get("completed"):
            del auth_flows[flow_id]
            return {"status": "authenticated", "provider": flow["provider"]}
        return {"status": "pending", "flow_id": flow_id, "instructions": "Use provider_login_callback to provide the redirect URL."}

    # --- Device code flows: poll token endpoint ---
    provider = flow["provider"]

    if provider == "openai":
        try:
            resp = await http_client.post(
                _OPENAI_TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": _OPENAI_CLIENT_ID,
                    "device_code": flow["device_code"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
            body = resp.json()
        except Exception as e:
            return {"error": f"Failed to poll OpenAI: {e}"}

        if resp.status_code == 200 and body.get("access_token"):
            _write_auth_json({
                "openai": {
                    "type": "oauth",
                    "access": body["access_token"],
                    "refresh": body.get("refresh_token", ""),
                    "expires": int(time.time() * 1000) + body.get("expires_in", 3600) * 1000,
                }
            })
            del auth_flows[flow_id]
            return {"status": "authenticated", "provider": "openai"}

        error = body.get("error", "")
        if error == "authorization_pending":
            return {"status": "pending", "flow_id": flow_id, "retry_after": flow.get("interval", 5)}
        if error == "slow_down":
            flow["interval"] = flow.get("interval", 5) + 5
            return {"status": "pending", "flow_id": flow_id, "retry_after": flow["interval"], "detail": "slow_down"}
        if error == "expired_token":
            del auth_flows[flow_id]
            return {"status": "expired", "flow_id": flow_id}
        return {"status": "error", "detail": body.get("error_description", error)}

    if provider == "github-copilot":
        try:
            resp = await http_client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": "Iv1.b507a08c87ecfe98",
                    "device_code": flow["device_code"],
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
                headers={"Accept": "application/json"},
                timeout=10,
            )
            body = resp.json()
        except Exception as e:
            return {"error": f"Failed to poll GitHub: {e}"}

        if body.get("access_token"):
            _write_auth_json({
                "github-copilot": {
                    "type": "oauth",
                    "access": body["access_token"],
                    "refresh": body.get("refresh_token", body["access_token"]),
                    "expires": 0,
                }
            })
            del auth_flows[flow_id]
            return {"status": "authenticated", "provider": "github-copilot"}

        error = body.get("error", "")
        if error == "authorization_pending":
            return {"status": "pending", "flow_id": flow_id, "retry_after": flow.get("interval", 5)}
        if error == "slow_down":
            flow["interval"] = flow.get("interval", 5) + 5
            return {"status": "pending", "flow_id": flow_id, "retry_after": flow["interval"], "detail": "slow_down"}
        if error == "expired_token":
            del auth_flows[flow_id]
            return {"status": "expired", "flow_id": flow_id}
        return {"status": "error", "detail": body.get("error_description", error)}

    return {"error": f"Cannot poll flow for provider '{provider}'."}


@mcp.tool(description="Complete an OAuth redirect flow by providing the callback URL. Use when the browser can't reach the server's localhost.")
async def provider_login_callback(ctx: Context, flow_id: str, callback_url: str) -> dict:
    auth_flows: dict[str, dict] = ctx.request_context.lifespan_context["auth_flows"]
    http_client: httpx.AsyncClient = ctx.request_context.lifespan_context["http_client"]

    flow = auth_flows.get(flow_id)
    if not flow:
        return {"error": f"Flow {flow_id} not found or expired."}
    if flow["type"] != "redirect":
        return {"error": "This flow is not a redirect flow. Use provider_login_poll instead."}
    if flow.get("expires_at", 0) < time.time():
        del auth_flows[flow_id]
        return {"status": "expired", "flow_id": flow_id}

    # Parse code and state from callback URL
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(callback_url)
    params = parse_qs(parsed.query)
    code = params.get("code", [None])[0]
    state = params.get("state", [None])[0]

    if not code:
        return {"error": "No 'code' parameter found in callback URL."}
    if state != flow["state"]:
        return {"error": "State mismatch — possible CSRF. Start a new flow."}

    provider = flow["provider"]
    verifier = flow["verifier"]
    token_url = flow["token_url"]
    redirect_uri = flow["redirect_uri"]

    # Exchange code for tokens
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }

    if provider == "anthropic":
        token_data["client_id"] = _ANTHROPIC_CLIENT_ID
    elif provider == "google":
        token_data["client_id"] = _GOOGLE_CLIENT_ID
        token_data["client_secret"] = _GOOGLE_CLIENT_SECRET

    try:
        resp = await http_client.post(
            token_url,
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"error": f"Token exchange failed: {resp.status_code} {resp.text}"}
        body = resp.json()
    except Exception as e:
        return {"error": f"Token exchange failed: {e}"}

    auth_key = _OPENCODE_PROVIDERS[provider].get("auth_key", provider)
    _write_auth_json({
        auth_key: {
            "type": "oauth",
            "access": body.get("access_token", ""),
            "refresh": body.get("refresh_token", ""),
            "expires": int(time.time() * 1000) + body.get("expires_in", 3600) * 1000,
        }
    })

    del auth_flows[flow_id]
    return {"status": "authenticated", "provider": provider}


@mcp.tool(description="Remove credentials for an OpenCode provider from auth.json.")
async def provider_logout(ctx: Context, provider: str) -> dict:
    if provider not in _OPENCODE_PROVIDERS:
        return {"error": f"Unknown provider '{provider}'. Known: {', '.join(_OPENCODE_PROVIDERS)}"}

    auth_key = _OPENCODE_PROVIDERS[provider].get("auth_key", provider)
    removed = _remove_auth_json_key(auth_key)
    if removed:
        return {"status": "logged_out", "provider": provider}
    return {"status": "not_found", "provider": provider, "detail": "Provider was not in auth.json."}


@mcp.tool(description="Get server info including active run count and system stats.")
async def get_server_info(ctx: Context) -> dict:
    runs: dict[str, RunState] = ctx.request_context.lifespan_context["runs"]
    config: dict = ctx.request_context.lifespan_context["config"]
    active = sum(1 for r in runs.values() if r.status == "running")
    return {
        "server_name": "poke-code",
        "version": "1.0.0",
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "default_engine": config.get("default_engine", "claude"),
        "engines": {
            "claude": shutil.which("claude") is not None,
            "opencode": shutil.which("opencode") is not None,
        },
        "active_runs": active,
        "total_runs": len(runs),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    host = "0.0.0.0"
    logger.info("Starting poke-code on %s:%d", host, port)
    app = mcp.http_app(
        middleware=[Middleware(DropNonMCPRoutes)],
        stateless_http=True,
    )
    uvicorn.run(app, host=host, port=port)
