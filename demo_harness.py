"""
demo_harness.py
===============
Chạy demo toàn bộ mock vulnerabilities mà KHÔNG cần API key hay LLM.
Dùng để xác minh môi trường giả lập hoạt động đúng trước khi chạy pipeline.

Sử dụng:
    python demo_harness.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mock_challenge.test_harness import run_harness_by_name

# ─────────────────────────────────────────────────────────────────────────────
# Test cases (known-good exploits & known-benign inputs)
# ─────────────────────────────────────────────────────────────────────────────

TEST_CASES: list[dict] = [
    # ── Path Traversal ────────────────────────────────────────────────────────
    {
        "harness":  "path_traversal",
        "label":    "Path Traversal – benign request (should NOT trigger)",
        "input":    {"filename": "index.html", "base_dir": "/var/www/html"},
        "expected": False,
    },
    {
        "harness":  "path_traversal",
        "label":    "Path Traversal – classic ../ exploit (should trigger)",
        "input":    {"filename": "../../etc/passwd", "base_dir": "/var/www/html"},
        "expected": True,
    },
    {
        "harness":  "path_traversal",
        "label":    "Path Traversal – secret config (should trigger)",
        "input":    {"filename": "../../../var/secret/config.txt", "base_dir": "/var/www/html"},
        "expected": True,
    },
    {
        "harness":  "path_traversal",
        "label":    "Path Traversal – flag file (should trigger)",
        "input":    {"filename": "../../../tmp/flag.txt", "base_dir": "/var/www/html"},
        "expected": True,
    },

    # ── SQL Injection ─────────────────────────────────────────────────────────
    {
        "harness":  "sql_injection",
        "label":    "SQL Injection – valid credentials (should NOT trigger)",
        "input":    {"username": "alice", "password": "password_alice_secure"},
        "expected": False,
    },
    {
        "harness":  "sql_injection",
        "label":    "SQL Injection – wrong password (should NOT trigger)",
        "input":    {"username": "alice", "password": "wrong"},
        "expected": False,
    },
    {
        "harness":  "sql_injection",
        "label":    "SQL Injection – OR 1=1 bypass (should trigger)",
        "input":    {"username": "admin' OR '1'='1", "password": "anything"},
        "expected": True,
    },
    {
        "harness":  "sql_injection",
        "label":    "SQL Injection – comment bypass (should trigger)",
        "input":    {"username": "admin'--", "password": ""},
        "expected": True,
    },

    # ── Integer Overflow ──────────────────────────────────────────────────────
    {
        "harness":  "integer_overflow",
        "label":    "Integer Overflow – safe values (should NOT trigger)",
        "input":    {"size": 100, "multiplier": 2},
        "expected": False,
    },
    {
        "harness":  "integer_overflow",
        "label":    "Integer Overflow – edge (should NOT trigger)",
        "input":    {"size": 1000000, "multiplier": 2000},
        "expected": False,
    },
    {
        "harness":  "integer_overflow",
        "label":    "Integer Overflow – INT32_MAX × 2 (should trigger)",
        "input":    {"size": 2147483647, "multiplier": 2},
        "expected": True,
    },
    {
        "harness":  "integer_overflow",
        "label":    "Integer Overflow – large values (should trigger)",
        "input":    {"size": 1073741825, "multiplier": 4},
        "expected": True,
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_demo() -> None:
    passed = 0
    failed = 0

    print("=" * 70)
    print("  Mock Vulnerability Harness – Demo")
    print("=" * 70)

    current_harness = ""
    for tc in TEST_CASES:
        if tc["harness"] != current_harness:
            current_harness = tc["harness"]
            print(f"\n── {current_harness.upper().replace('_', ' ')} {'─'*40}")

        result    = run_harness_by_name(tc["harness"], json.dumps(tc["input"]))
        triggered = result.get("triggered", False)
        ok        = triggered == tc["expected"]

        if ok:
            passed += 1
            status = "✓ PASS"
        else:
            failed += 1
            status = "✗ FAIL"

        print(f"\n  [{status}]  {tc['label']}")
        print(f"           Input    : {json.dumps(tc['input'])}")
        print(f"           Triggered: {triggered}  (expected: {tc['expected']})")
        if result.get("flag"):
            print(f"           Flag     : {result['flag']}")
        output = result.get("output", "")
        print(f"           Output   : {output[:120]}{'…' if len(output) > 120 else ''}")

    total = passed + failed
    print("\n" + "=" * 70)
    print(f"  Results: {passed}/{total} passed", end="")
    if failed:
        print(f"  |  {failed} FAILED ← investigate above!", end="")
    print("\n" + "=" * 70)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    run_demo()
