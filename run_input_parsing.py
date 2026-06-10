#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path


def choose_python(skill_dir: Path) -> str:
    env_python = os.environ.get("INPUT_PARSING_FUNC_PYTHON")
    if env_python:
        return env_python

    win_venv = skill_dir / "scripts" / "vulfunc_ranker" / ".venv" / "Scripts" / "python.exe"
    if win_venv.exists():
        return str(win_venv)

    unix_venv = skill_dir / "scripts" / "vulfunc_ranker" / ".venv" / "bin" / "python"
    if unix_venv.exists():
        return str(unix_venv)

    return "python"


def main() -> int:
    if len(sys.argv) < 2:
        print("Error: missing input_bin")
        print("Usage: python ./scripts/run_input_parsing.py <input_bin> [optional flags]")
        return 1

    skill_dir = Path(__file__).resolve().parents[1]
    runner = skill_dir / "scripts" / "vulfunc_ranker" / "vulfunc_rank.py"

    python_exec = choose_python(skill_dir)
    cmd = [python_exec, str(runner), *sys.argv[1:]]

    print(f"Python executable: {python_exec}")
    print(f"Run command: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=str(skill_dir))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
