#!/usr/bin/env python3
"""bulla as an MCP server.

Exposes the hermetic cell as MCP tools, so any client (Claude Desktop, Cursor, Windsurf, Cline, ...)
can run a model's code in a sealed, deterministic sandbox and get back not raw stdout but a **signed,
verifiable receipt** that the isolation seal held:

  * run_attested — run a shell command in a throw-away hermetic cell; return the receipt summary
                   {seal_ok, exit_code, net_ns, inputs_root, stdout_sha256, egress, receipt, pubkey,
                   body_digest}. Optionally allow *scoped* egress to named hosts (mediated + hashed).
  * verify_receipt — verify a receipt file offline {intact, sig_ok, digest_ok, chain_ok, seal_ok}.

The heavy lifting is the `bulla` binary; this is a thin wrapper (only the `mcp` package). Config:

  BULLA_BIN   path to the bulla binary            (default: "bulla" on PATH)
  BULLA_WSL   "<distro>:<linux path to bulla>"    run bulla through WSL from a Windows host; the work
                                                  dir is translated C:\\… -> /mnt/c/…
  BULLA_WORK  default work dir for run_attested   (default: the client's cwd)

Run it directly for a stdio server:  python adapters/mcp/bulla_mcp.py
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Optional, TypedDict


class RunResult(TypedDict):
    """The typed run-result returned as `structuredContent` (behind an outputSchema)."""
    seal_ok: Optional[bool]         # did a hermetic seal hold (no egress + private root + deterministic)?
    exit_kind: Optional[str]        # code | signal | timeout | setup_failed
    exit_code: Optional[int]
    wall_ms: Optional[int]
    network: Optional[str]          # deny | allow
    net_ns: Optional[bool]          # empty network namespace (no raw egress)?
    inputs_root: Optional[str]      # content-addressed digest of the work dir
    stdout_sha256: Optional[str]
    egress: Optional[dict[str, Any]]  # mediated egress: {calls, denied, allowlist, allowlist_digest, log_head}
    git_sealed: Optional[bool]
    receipt: Optional[str]          # path to the signed receipt.json
    pubkey: Optional[str]
    body_digest: Optional[str]
    seal_notes: list[str]
    rendered: str                   # short human-facing summary


def _to_wsl_path(p: str) -> str:
    p = str(p)
    if len(p) > 2 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:].replace("\\", "/")
    return p.replace("\\", "/")


def _bulla_argv(sub: str) -> tuple[list[str], bool]:
    """Return (argv-prefix ending with the subcommand, via_wsl)."""
    wsl = os.environ.get("BULLA_WSL")
    if wsl and ":" in wsl:
        distro, linux_bin = wsl.split(":", 1)
        return (["wsl.exe", "-d", distro, "--", linux_bin, sub], True)
    return ([os.environ.get("BULLA_BIN", "bulla"), sub], False)


def _err(msg: str) -> RunResult:
    return {"seal_ok": None, "exit_kind": None, "exit_code": None, "wall_ms": None,
            "network": None, "net_ns": None, "inputs_root": None, "stdout_sha256": None,
            "egress": None, "git_sealed": None, "receipt": None, "pubkey": None,
            "body_digest": None, "seal_notes": [], "rendered": msg}


def bulla_run(command: str, cwd: str | None = None, timeout: int = 120,
              egress_allow: list[str] | None = None) -> RunResult:
    """Run `command` in a hermetic cell and return the typed receipt summary."""
    work = cwd or os.environ.get("BULLA_WORK") or os.getcwd()
    prefix, via_wsl = _bulla_argv("run")
    work_arg = _to_wsl_path(work) if via_wsl else work
    argv = [*prefix, "--work", work_arg, "--json", "--wall-ms", str(timeout * 1000)]
    for host in (egress_allow or []):
        argv += ["--egress-allow", host]
    argv += ["--", "sh", "-c", command]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout + 30)
    except FileNotFoundError:
        return _err("error: `bulla` not found. Build it (cargo build --release -p bulla-cli) and set "
                    "BULLA_BIN, or set BULLA_WSL=<distro>:<path-to-bulla> on a Windows host.")
    except subprocess.TimeoutExpired:
        return {**_err(f"error: bulla timed out after {timeout}s"), "exit_kind": "timeout"}
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError:
        return _err((r.stderr or r.stdout or "bulla produced no JSON").strip()[:500])
    seal = "SEAL HELD" if d.get("seal_ok") else "SEAL BROKEN"
    eg = d.get("egress")
    eg_txt = f" · egress {eg['calls']} call(s), {eg['denied']} denied" if eg else ""
    d["rendered"] = (f"[bulla] {seal}  exit={d.get('exit_code')}  net_ns={d.get('net_ns')}"
                     f"{eg_txt}  · signed receipt at {d.get('receipt')}")
    return d  # type: ignore[return-value]


def bulla_verify(receipt_path: str) -> dict[str, Any]:
    """Verify a receipt file offline; return {intact, sig_ok, digest_ok, chain_ok, seal_ok, ...}."""
    prefix, via_wsl = _bulla_argv("verify")
    path_arg = _to_wsl_path(receipt_path) if via_wsl else receipt_path
    argv = [*prefix, "--json", path_arg]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
    except FileNotFoundError:
        return {"error": "`bulla` not found (set BULLA_BIN or BULLA_WSL)."}
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"error": (r.stderr or r.stdout or "no JSON").strip()[:500]}


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP        # bundled in the official SDK (mcp 1.x)
    except ImportError:
        try:
            from fastmcp import FastMCP               # standalone FastMCP 2.x
        except ImportError:
            raise SystemExit("The MCP SDK is required: `pip install 'mcp<2'` (bundled FastMCP) "
                             "or `pip install fastmcp`. See adapters/mcp/README.md.")
    mcp = FastMCP("bulla")

    @mcp.tool()
    def run_attested(command: str, cwd: str = "", timeout: int = 120,
                     egress_allow: list[str] | None = None) -> RunResult:
        """Run a shell command in a HERMETIC, deterministic cell (no root, no network by default) and
        return a SIGNED, verifiable receipt as structured data — {seal_ok, exit_code, net_ns,
        inputs_root, stdout_sha256, egress, git_sealed, receipt, pubkey, body_digest, rendered}. Your
        code runs in a vacuum: fresh namespaces, empty network namespace, pivot_root, seccomp, fixed
        env. `seal_ok` says whether a hermetic seal held; `receipt` is a file anyone can re-check with
        `bulla verify` (or the verify_receipt tool). Prefer this over running code directly when you
        need the result to be trustworthy/auditable.

        command:      the shell command to run (e.g. "cargo test", "pytest -q", "python strat.py").
        cwd:          working directory (default: BULLA_WORK or the server's cwd).
        timeout:      seconds before the run is killed (default 120).
        egress_allow: optional list of hosts the cell may reach through the *mediated* egress broker
                      (the network namespace stays empty; every call is allowlist-checked and hashed
                      into the receipt). Omit for no egress at all.
        """
        return bulla_run(command, cwd or None, timeout, egress_allow)

    @mcp.tool()
    def verify_receipt(receipt: str) -> dict[str, Any]:
        """Verify a bulla receipt file offline (no re-run, no network): checks the Ed25519 signature,
        the body digest, and the event chain, and reports the seal verdict — {intact, sig_ok,
        digest_ok, chain_ok, seal_ok, notes}. `intact` means unforged + internally consistent."""
        return bulla_verify(receipt)

    mcp.run()


if __name__ == "__main__":
    main()
