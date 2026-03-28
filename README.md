# poke-code

MCP server that runs autonomous coding agents in sandboxed workspaces. Clone a repo, execute tasks with Claude Agent SDK or OpenCode CLI, review diffs, commit and push — all over MCP.

## Features

- **Two engines** — Claude Agent SDK and OpenCode CLI
- **Plan-first workflow** — `plan` → `approve` → `implement` for controlled execution
- **Full mode** — skip planning for quick fixes
- **Sandboxed workspaces** — each run gets its own cloned repo
- **Webhook notifications** — progress and completion callbacks
- **Auth** — API key verification via Bearer token

## Quick Start

```bash
# Clone
git clone https://github.com/kacperkwapisz/poke-code.git
cd poke-code

# Configure
cp .env.example .env
cp config.example.yml config.yml
# Edit .env with your ANTHROPIC_API_KEY and MCP_API_KEY

# Run
pip install -r requirements.txt
python src/server.py
```

Server starts on `http://localhost:3000/mcp` (streamable HTTP transport).

## Docker

```bash
docker build -t poke-code .
docker run -p 3000:3000 \
  -e MCP_API_KEY=your-secret \
  -e ENVIRONMENT=production \
  poke-code
```

Or pull from GHCR:

```bash
# Latest (staging, built from main)
docker pull ghcr.io/kacperkwapisz/poke-code:latest

# Release
docker pull ghcr.io/kacperkwapisz/poke-code:1.0.0
```

## Tools

| Tool | Description |
|------|-------------|
| `clone_and_init` | Clone a repo and create a workspace |
| `execute_task` | Run a coding task (`mode`: `plan`, `implement`, or `full`) |
| `approve_plan` | Approve or reject a plan before implementation |
| `get_status` | Poll run progress, phase, cost, and plan status |
| `get_output` | Paginated activity log |
| `get_diff` | Git diff of workspace changes |
| `commit_and_push` | Commit and push changes |
| `cancel_task` | Cancel a running task |
| `cleanup_run` | Delete workspace and run state |
| `list_runs` | List all runs |
| `get_server_info` | Server health and capabilities |

## Workflow

### Plan-first (recommended)

```
clone_and_init(repo_url)           → run_id
execute_task(run_id, task, mode="plan")  → agent explores, produces plan
get_status(run_id)                 → poll until completed, read plan_text
approve_plan(run_id, approve=True) → approved
execute_task(run_id, task, mode="implement") → agent implements the plan
get_diff(run_id)                   → review changes
commit_and_push(run_id, message, branch)
```

### Quick fix

```
clone_and_init(repo_url)           → run_id
execute_task(run_id, task)         → mode="full" by default
get_diff(run_id)
commit_and_push(run_id, message, branch)
```

## Configuration

See [`config.example.yml`](config.example.yml) for all options including engine settings, concurrency limits, and webhook configuration.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MCP_API_KEY` | Production | Bearer token for MCP auth |
| `ENVIRONMENT` | No | Set to `production` to require `MCP_API_KEY` |
| `CONFIG_PATH` | No | Path to config file (default: `config.yml`) |
| `PORT` | No | Server port (default: `3000`) |

Claude Code CLI authenticates via the user's existing subscription. No API key needed.

## License

MIT
