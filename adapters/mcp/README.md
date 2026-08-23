# bulla as an MCP server

Attach the hermetic cell to any [MCP](https://modelcontextprotocol.io) client — Claude Desktop, Cursor,
Windsurf, Cline, Roo Code — so a model can run its own code in a **sealed, deterministic sandbox** and get
back not raw stdout but a **signed, verifiable receipt** that the isolation seal held. One file, one small
dependency (`mcp<2` or `fastmcp`).

## Tools it exposes

| Tool | What it does |
|---|---|
| `run_attested(command, cwd?, timeout?, egress_allow?)` | Run a shell command in a throw-away hermetic cell (no root, no network by default). Returns the receipt as MCP **`structuredContent`**: `{seal_ok, exit_code, net_ns, inputs_root, stdout_sha256, egress, git_sealed, receipt, pubkey, body_digest, rendered}`. `receipt` is a file anyone can re-check. `egress_allow` optionally permits *scoped* network to named hosts through the mediated broker (every call hashed into the receipt). |
| `verify_receipt(receipt)` | Verify a receipt file offline — Ed25519 signature, body digest, event chain, and the seal verdict — `{intact, sig_ok, digest_ok, chain_ok, seal_ok, notes}`. |

The model learns its code ran **in a vacuum** and hands back proof, instead of asking you to trust an
un-attested log.

## Install

```bash
pip install 'mcp<2'      # the MCP Python SDK (bundled FastMCP)  —  OR:  pip install fastmcp
cargo build --release -p bulla-cli   # if you don't already have the bulla binary
```

> The server imports `FastMCP` from the official SDK (`mcp.server.fastmcp`) and falls back to the
> standalone `fastmcp` package, so either install works.

## Configure (one block)

`command` runs the server over stdio. Point `BULLA_BIN` at the `bulla` binary (or leave it if `bulla` is on
`PATH`). Config file per client: Claude Desktop → `claude_desktop_config.json`; Cursor → `~/.cursor/mcp.json`;
Windsurf → `~/.codeium/windsurf/mcp_config.json`; Cline/Roo → the extension's MCP settings.

**Linux / macOS (bulla on PATH or via `BULLA_BIN`):**
```json
{
  "mcpServers": {
    "bulla": {
      "command": "python",
      "args": ["/abs/path/to/bulla/adapters/mcp/bulla_mcp.py"],
      "env": { "BULLA_BIN": "/abs/path/to/bulla" }
    }
  }
}
```

**Windows host, bulla in WSL** (the sandbox is Linux-only; run the binary through WSL and let the server
translate `C:\…` → `/mnt/c/…`):
```json
{
  "mcpServers": {
    "bulla": {
      "command": "python",
      "args": ["C:\\path\\to\\bulla\\adapters\\mcp\\bulla_mcp.py"],
      "env": { "BULLA_WSL": "Ubuntu:/home/you/.cargo/bin/bulla" }
    }
  }
}
```

## Environment

| Var | Meaning | Default |
|---|---|---|
| `BULLA_BIN` | path to the `bulla` binary | `bulla` on `PATH` |
| `BULLA_WSL` | `<distro>:<linux path to bulla>` — run through WSL from Windows | unset |
| `BULLA_WORK` | default work dir for `run_attested` | the server's cwd |

## Why

Every other way to give a model a sandbox hands it (and you) an **unsigned** log the operator can edit.
`run_attested` hands back a receipt bound to the enforced policy — network off (or a signed allowlist),
private root, deterministic env, outputs by hash — that anyone can verify with `verify_receipt` and no
trust in the runner beyond its key. See the [technical report](../../docs/REPORT.md).
