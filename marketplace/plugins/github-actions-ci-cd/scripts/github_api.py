#!/usr/bin/env python3
"""
GitHub REST and Actions API wrapper (stdlib urllib, no extra deps)

Github Actions Ci Cd plugin helper script.

Usage:
    python3 github_api.py status
    python3 github_api.py logs
    python3 github_api.py trigger

Required environment variables:
    GITHUB_ACTIONS_CI_CD_HOST    Base URL or hostname for Github Actions Ci Cd
    GITHUB_ACTIONS_CI_CD_TOKEN   API token or credential (if required)
    GITHUB_ACTIONS_CI_CD_ORG     Organization or namespace (if applicable)
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error


def get_config() -> dict:
    return {
        "host":  os.environ.get("GITHUB_ACTIONS_CI_CD_HOST", "").rstrip("/"),
        "token": os.environ.get("GITHUB_ACTIONS_CI_CD_TOKEN", ""),
        "org":   os.environ.get("GITHUB_ACTIONS_CI_CD_ORG", ""),
    }


def check_config() -> dict:
    cfg = get_config()
    if not cfg["host"]:
        print(f"ERROR: GITHUB_ACTIONS_CI_CD_HOST is not set", file=sys.stderr)
        print(f"  export GITHUB_ACTIONS_CI_CD_HOST=<github actions ci cd-url>", file=sys.stderr)
        sys.exit(1)
    return cfg


def auth_headers(cfg: dict) -> dict:
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if cfg["token"]:
        h["Authorization"] = f"Bearer {cfg['token']}"
    return h


def api_get(url: str, headers: dict) -> dict:
    """GET request returning parsed JSON."""
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"HTTP {e.code} {e.reason}: {body[:200]}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        sys.exit(1)


def cmd_status(cfg: dict, args) -> None:
    """Latest workflow runs with pass/fail status per branch."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/status"
    # data = api_get(url, auth_headers(cfg))
    # print(json.dumps(data, indent=2))
    print(f"[github-actions-ci-cd] status: not yet implemented")

def cmd_logs(cfg: dict, args) -> None:
    """Stream logs from a workflow run or specific job step."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/logs"
    # data = api_get(url, auth_headers(cfg))
    # print(json.dumps(data, indent=2))
    print(f"[github-actions-ci-cd] logs: not yet implemented")

def cmd_trigger(cfg: dict, args) -> None:
    """Manually dispatch a workflow with optional inputs."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/trigger"
    # data = api_get(url, auth_headers(cfg))
    # print(json.dumps(data, indent=2))
    print(f"[github-actions-ci-cd] trigger: not yet implemented")

def cmd_artifacts(cfg: dict, args) -> None:
    """List, download, or expire build artifacts."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/artifacts"
    # data = api_get(url, auth_headers(cfg))
    # print(json.dumps(data, indent=2))
    print(f"[github-actions-ci-cd] artifacts: not yet implemented")

def cmd_debug(cfg: dict, args) -> None:
    """Analyze a failed run and suggest root-cause fixes."""
    host = cfg["host"]
    # TODO: implement — call host API and print results
    # url = f"{host}/api/v1/debug"
    # data = api_get(url, auth_headers(cfg))
    # print(json.dumps(data, indent=2))
    print(f"[github-actions-ci-cd] debug: not yet implemented")


def main() -> None:
    parser = argparse.ArgumentParser(description="GitHub REST and Actions API wrapper (stdlib urllib, no extra deps)")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    sub.add_parser("status", help="Latest workflow runs with pass/fail status per branch")
    sub.add_parser("logs", help="Stream logs from a workflow run or specific job step")
    sub.add_parser("trigger", help="Manually dispatch a workflow with optional inputs")
    sub.add_parser("artifacts", help="List, download, or expire build artifacts")
    sub.add_parser("debug", help="Analyze a failed run and suggest root-cause fixes")
    args = parser.parse_args()
    cfg = check_config()
    if args.command == "status":
        cmd_status(cfg, args)
    elif args.command == "logs":
        cmd_logs(cfg, args)
    elif args.command == "trigger":
        cmd_trigger(cfg, args)
    elif args.command == "artifacts":
        cmd_artifacts(cfg, args)
    elif args.command == "debug":
        cmd_debug(cfg, args)


if __name__ == "__main__":
    main()
