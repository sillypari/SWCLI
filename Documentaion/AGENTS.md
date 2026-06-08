# Repository Guidelines

## Project Structure & Module Organization

This is a Python CLI project for the Sidewinder wireless toolkit. Core library code lives in `sidewinder/`: `core/` contains scanner, monitor, session, config, cleanup, and subprocess logic; `adapters/` contains chipset-specific adapter support; `attacks/` contains attack modules. The user-facing CLI lives in `swcli/`, with `swcli/cli.py` and `swcli/repl/` for the interactive shell UI. Top-level `test_*.py` files are focused probe scripts. Markdown files such as `SWCLI_CONTEXT.md`, `SWCLI_PIPELINES.md`, and `TestBugs.md` document design notes and audit findings.

## Build, Test, and Development Commands

No packaging metadata or Makefile is currently committed, so run modules directly from the repository root.

- `python -m swcli`: start the interactive SWCLI REPL.
- `python -m swcli deps`: check required and optional external binaries.
- `python -m swcli adapters`: list wireless interfaces.
- `python -m swcli monitor status <iface>`: inspect interface mode.
- `python test_loop.py`: run an individual probe script. Replace with another `test_*.py` as needed.

Many operational commands may require `sudo`; avoid disruptive monitor-mode changes, service kills, or attacks without explicit confirmation.

## Coding Style & Naming Conventions

Use Python 3 with 4-space indentation. Follow the existing style: `snake_case` for functions and variables, `PascalCase` for classes, short argparse handler names like `handle_scan`, and async handlers where hardware workflows are asynchronous. Keep CLI output direct and actionable. Prefer reusable modules under `sidewinder/core/` over adding logic directly to `swcli/cli.py`.

## Testing Guidelines

There is no formal pytest configuration yet. Existing `test_*.py` files are script-style checks. Name new checks `test_<behavior>.py` at the repository root unless a test package is introduced. For pure logic, prefer deterministic tests that do not require wireless hardware, root, or live network state.

## Commit & Pull Request Guidelines

Recent history uses concise imperative commits, sometimes with Conventional Commit prefixes, for example `feat: implement adapter factory...` and `Add stale eviction loop...`. Pull requests should include a summary, validation commands, hardware or OS assumptions, and screenshots when CLI presentation changes. Link related issues or audit notes when applicable.

## Security & Configuration Tips

Treat capture files, interface names, MAC addresses, and wordlists as sensitive operational data unless intentionally sanitized.
