#!/usr/bin/env python3
import asyncio
import hmac
import json
import logging
import os
import re
import shutil
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
        if scope["type"] == "http" and not scope["path"].startswith("/mcp"):
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
_SECRET_ENV_KEYS = {"MCP_API_KEY", "WEBHOOK_BEARER_TOKEN"}

_SAFE_REPO_URL = re.compile(
    r"^https?://[a-zA-Z0-9._\-]+(?::\d+)?/[a-zA-Z0-9._\-/]+(?:\.git)?$"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_env() -> dict[str, str]:
    """Return current env minus secrets — safe to pass to subprocesses."""
    return {k: v for k, v in os.environ.items() if k not in _SECRET_ENV_KEYS}


def _subprocess_env(config: dict) -> dict[str, str]:
    """Build env for subprocesses — safe env + webhook token for hooks."""
    env = _safe_env()
    bearer_token = config.get("webhook_bearer_token", "")
    if bearer_token:
        env["POKE_WEBHOOK_TOKEN"] = bearer_token
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
            "status": self.status,
            "phase": self.phase,
            "engine": self.engine,
            "current_tool": self.current_tool,
            "current_file": self.current_file,
            "turns_used": self.turns_used,
            "turns_max": self.turns_max,
            "cost_usd": self.cost_usd,
            "budget_usd": self.budget_usd,
            "tokens_used": self.tokens_used,
            "duration_seconds": round(duration, 1),
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

def _write_claude_hooks(repo_path: str, run_id: str, config: dict) -> None:
    """Write .claude/settings.json with webhook hooks if webhook_url is configured."""
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return

    hooks_dir = os.path.join(repo_path, ".claude")
    os.makedirs(hooks_dir, exist_ok=True)

    # Shell script that POSTs hook events to the webhook.
    # Auth token is passed via env var (POKE_WEBHOOK_TOKEN) to avoid leaking to the filesystem.
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

    # Merge with existing settings if present
    settings_path = os.path.join(hooks_dir, "settings.json")
    existing: dict = {}
    if os.path.isfile(settings_path):
        try:
            with open(settings_path) as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    poke_hooks = {
        "EditTool": [{"matcher": "", "hooks": [{"type": "command", "command": f"{hook_script} edit"}]}],
        "WriteTool": [{"matcher": "", "hooks": [{"type": "command", "command": f"{hook_script} write"}]}],
        "Stop": [{"matcher": "", "hooks": [{"type": "command", "command": f"{hook_script} stop"}]}],
    }
    existing.setdefault("hooks", {}).update(poke_hooks)

    with open(settings_path, "w") as f:
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
        run.cost_usd = event.get("total_cost_usd", 0.0)
        run.turns_used = event.get("num_turns", run.turns_used)
        usage = event.get("usage", {})
        run.tokens_used = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
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
    if run.budget_usd:
        cmd.extend(["--max-budget-usd", str(run.budget_usd)])
    if allowed_tools:
        cmd.extend(["--allowedTools", ",".join(allowed_tools)])
    if disallowed_tools:
        cmd.extend(["--disallowedTools", ",".join(disallowed_tools)])
    if system_prompt:
        cmd.extend(["--append-system-prompt", system_prompt])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=run.repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_subprocess_env(config),
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
            run.tokens_used += tokens.get("input", 0) + tokens.get("output", 0)
        reason = event.get("reason", "")
        if reason == "stop":
            run.add_activity({"type": "step_finish", "detail": "Step finished (stop)"})


async def run_opencode_task(
    run: RunState,
    task_description: str,
    config: dict,
    http_client: httpx.AsyncClient,
    system_prompt: str | None = None,
) -> None:
    opencode_config = config.get("opencode", {})
    model = opencode_config.get("model", "")
    progress_interval = config.get("webhook_progress_interval", 10)

    run.status = "running"
    run.phase = "thinking"
    run.started_at = _now()
    run.add_activity({"type": "start", "detail": "Task execution started (opencode)"})

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

    # Write Claude Code hooks for webhook progress (optional, claude engine only)
    if resolved_engine == "claude":
        _write_claude_hooks(run.repo_path, run_id, config)

    # Preserve plan_text for implement mode before reset
    saved_plan = run.plan_text if mode == "implement" else None

    # Reset run state for (re-)execution
    run.status = "running"
    run.phase = "thinking"
    run.engine = resolved_engine
    run.execution_mode = mode
    run.activity_log.clear()
    run.files_modified.clear()
    run.current_tool = None
    run.current_file = None
    run.turns_used = 0
    run.cost_usd = 0.0
    run.tokens_used = 0
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
            )
        )
    else:
        run.task = asyncio.create_task(
            run_claude_task(
                run, task_description, config, http_client,
                system_prompt=system_prompt or None,
            )
        )

    return {"run_id": run_id, "status": "running", "engine": resolved_engine}


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
        if shutil.which("opencode"):
            return {"authenticated": True, "engine": "opencode", "method": "cli"}
        return {"authenticated": False, "engine": "opencode", "instructions": "opencode CLI is not installed."}

    return {"error": f"Unknown engine '{engine}'"}


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
