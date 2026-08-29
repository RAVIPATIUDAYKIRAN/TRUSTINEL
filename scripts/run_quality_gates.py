#!/usr/bin/env python3
"""
TRUSTINEL — Local Quality & Security Gates Runner
Executes comprehensive automated checks prior to committing or deploying code:
1. Python backend compilation check
2. Automated pytest suite execution
3. Secret scanning security audit
4. Chrome Extension build validation
"""

import os
import re
import sys
import subprocess
from pathlib import Path

# Base paths
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
EXTENSION_DIR = ROOT_DIR / "extension"


def print_step(title: str):
    print(f"\n==================================================")
    print(f"  {title}")
    print(f"==================================================")


def run_command(cmd: list[str], cwd: Path) -> bool:
    cmd_str = " ".join(cmd)
    print(f"[RUNNING] {cmd_str} (in {cwd.name})")
    try:
        res = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
        if res.returncode == 0:
            print(f"[SUCCESS] {cmd_str}")
            return True
        else:
            print(f"[FAILED] {cmd_str}")
            print(f"STDOUT:\n{res.stdout}")
            print(f"STDERR:\n{res.stderr}")
            return False
    except Exception as exc:
        print(f"[ERROR] Could not execute '{cmd_str}': {exc}")
        return False


def check_python_compilation() -> bool:
    print_step("Check 1: Python Compilation Audit")
    return run_command([sys.executable, "-m", "compileall", "app"], cwd=BACKEND_DIR)


def check_pytest_suite() -> bool:
    print_step("Check 2: Backend Pytest Suite Execution")
    pytest_bin = BACKEND_DIR / ".venv" / "Scripts" / "pytest.exe"
    if not pytest_bin.exists():
        pytest_bin = Path(sys.executable).parent / "pytest"
    
    cmd = [str(pytest_bin) if pytest_bin.exists() else "pytest", "tests/"]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    
    print(f"[RUNNING] {' '.join(cmd)} (in {BACKEND_DIR.name})")
    res = subprocess.run(cmd, cwd=BACKEND_DIR, text=True, capture_output=True, env=env)
    if res.returncode == 0:
        # Extract passed test count summary line
        last_line = [line for line in res.stdout.splitlines() if "passed" in line][-1] if res.stdout else ""
        print(f"[SUCCESS] Pytest suite passed cleanly! ({last_line.strip()})")
        return True
    else:
        print(f"[FAILED] Pytest suite failed.")
        print(f"STDOUT:\n{res.stdout}")
        print(f"STDERR:\n{res.stderr}")
        return False


def check_secret_scanning() -> bool:
    print_step("Check 3: Secret Scanning Security Audit")
    
    # Patterns to flag for unmasked secrets
    secret_patterns = [
        (re.compile(r"sk-[a-zA-Z0-9]{32,}", re.IGNORECASE), "OpenAI API Key Pattern"),
        (re.compile(r"Bearer\s+([a-zA-Z0-9\._\-]{30,})", re.IGNORECASE), "Bearer Token Pattern"),
        (re.compile(r"-----BEGIN PRIVATE KEY-----", re.IGNORECASE), "Private Key Header"),
    ]

    ignored_dirs = {".git", ".venv", "node_modules", "dist", "__pycache__", ".pytest_cache"}
    ignored_files = {"run_quality_gates.py", "test_observability.py", "test_api_integration.py", "logging.py", "verify_task5_manual.py"}

    findings = []

    for search_dir in [BACKEND_DIR, EXTENSION_DIR]:
        for root, dirs, files in os.walk(search_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file in files:
                if file in ignored_files or file.endswith((".pyc", ".png", ".ico", ".jpg", ".lock")):
                    continue
                file_path = Path(root) / file
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for pattern, desc in secret_patterns:
                        matches = pattern.findall(content)
                        if matches:
                            # Filter out placeholder strings like sk-proj-1234567890
                            real_matches = [
                                m for m in matches 
                                if "1234567890" not in str(m) and "secretpassword" not in str(m)
                            ]
                            if real_matches:
                                findings.append((file_path, desc, len(real_matches)))
                except Exception:
                    pass

    if findings:
        print(f"[FAILED] Potential unmasked secrets detected!")
        for path, desc, count in findings:
            print(f"  - {path.relative_to(ROOT_DIR)}: {desc} ({count} match(es))")
        return False
    else:
        print(f"[SUCCESS] Secret scanning passed cleanly! Zero unmasked secrets found.")
        return True


def check_extension_build() -> bool:
    print_step("Check 4: Chrome Extension Build Validation")
    npm_bin = "npm.cmd" if sys.platform == "win32" else "npm"
    return run_command([npm_bin, "run", "build"], cwd=EXTENSION_DIR)


def main():
    print(f"TRUSTINEL Quality & Security Gates Verification")
    print(f"Root Directory: {ROOT_DIR}")

    results = {
        "Python Compilation": check_python_compilation(),
        "Pytest Suite": check_pytest_suite(),
        "Secret Scanning Audit": check_secret_scanning(),
        "Extension Build": check_extension_build(),
    }

    print_step("QUALITY GATES SUMMARY")
    all_passed = True
    for check_name, passed in results.items():
        status_str = "[PASS]" if passed else "[FAIL]"
        print(f"  {status_str:<8} {check_name}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\nALL QUALITY & SECURITY GATES PASSED CLEANLY!")
        sys.exit(0)
    else:
        print("\nONE OR MORE QUALITY GATES FAILED. FIX ISSUES BEFORE COMMITTING.")
        sys.exit(1)


if __name__ == "__main__":
    main()
