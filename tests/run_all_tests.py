"""
Master test runner for AEGIS-X.

Runs every module's pytest suite, in dependency order, and prints one
consolidated pass/fail summary at the end — instead of having to run
five separate `pytest` commands and manually track which ones passed.

Written in Python (not bash/PowerShell) so the SAME script runs
identically on Windows, macOS, and Linux — subprocess handling, path
separators, and exit codes all behave consistently across platforms this
way, which a shell script can't guarantee without maintaining two
separate versions that could drift out of sync.

Usage:
    python tests/run_all_tests.py                 # run everything
    python tests/run_all_tests.py --fast           # skip the two slow
                                                     # full-stack Module 9
                                                     # tests that start a
                                                     # real server
    python tests/run_all_tests.py --module backend # run just one suite
"""

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# (display name, test path relative to repo root, module dir to run
# pytest from — pytest needs to run FROM each module's own directory so
# its local pytest.ini/conftest.py is picked up correctly)
TEST_SUITES: list[tuple[str, str, str]] = [
    ("Backend (Modules 2-3)", "tests", "backend"),
    ("AI Models (Modules 5-6)", "ai_engine/tests", "."),
    ("RAG (Module 7)", "rag/tests", "."),
    ("Multi-Agent AI (Module 8)", "ai_engine/agents/tests", "."),
    ("Integration (Module 9)", "ai_engine/integration/tests", "."),
]

# Slow test FUNCTION NAMES (not full paths) to exclude with --fast via -k.
# Deliberately name-based rather than path-based: --deselect requires an
# exact node id match, and that path is relative to whichever pytest.ini
# pytest decides is the "rootdir" for a given invocation — which turned
# out to silently differ from what was assumed here (ai_engine/pytest.ini
# gets picked up as rootdir when targeting anything under ai_engine/,
# shifting all relative paths). -k matches by substring against the test
# name only, so it's immune to that ambiguity entirely.
SLOW_TEST_NAMES = [
    "test_full_pipeline_writes_real_alert_to_real_backend",
    "test_investigated_alert_has_real_report_attached",
]


@dataclass
class SuiteResult:
    name: str
    passed: bool
    summary_line: str
    duration_seconds: float
    skipped: bool = False
    skip_reason: str = ""


def _run_suite(name: str, test_path: str, run_from: str, fast: bool) -> SuiteResult:
    run_dir = REPO_ROOT / run_from
    full_test_path = REPO_ROOT / run_from / test_path if run_from != "." else REPO_ROOT / test_path

    if not full_test_path.exists():
        return SuiteResult(
            name,
            passed=False,
            summary_line="",
            duration_seconds=0.0,
            skipped=True,
            skip_reason=f"'{full_test_path}' not found — module not installed/present.",
        )

    cmd = [sys.executable, "-m", "pytest", str(test_path), "-q", "--no-header", "-p", "no:cacheprovider"]
    if fast and SLOW_TEST_NAMES:
        exclusion_expr = " and ".join(f"not {name}" for name in SLOW_TEST_NAMES)
        cmd += ["-k", exclusion_expr]

    start = time.time()
    result = subprocess.run(cmd, cwd=str(run_dir), capture_output=True, text=True)
    duration = time.time() - start

    # pytest's actual result summary always goes to stdout; stderr often
    # carries unrelated warnings (e.g. from Python's warnings module) that
    # would otherwise push the real summary out of the "last line" position
    # when the two streams are naively concatenated.
    stdout_lines = [line for line in result.stdout.strip().splitlines() if line.strip()]
    summary_line = stdout_lines[-1] if stdout_lines else "(no output captured on stdout — check stderr)"

    passed = result.returncode == 0
    return SuiteResult(name, passed=passed, summary_line=summary_line.strip(), duration_seconds=duration)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all AEGIS-X test suites and print one consolidated summary.")
    parser.add_argument(
        "--fast", action="store_true", help="Skip the two slow full-stack Module 9 tests that start a real server."
    )
    parser.add_argument(
        "--module", default=None, help="Run only one module's suite (partial name match, e.g. 'backend', 'agents')."
    )
    args = parser.parse_args()

    suites = TEST_SUITES
    if args.module:
        suites = [s for s in suites if args.module.lower() in s[0].lower() or args.module.lower() in s[2].lower()]
        if not suites:
            print(f"No suite matches '--module {args.module}'. Available: {[s[0] for s in TEST_SUITES]}")
            return 1

    print("=" * 70)
    print("AEGIS-X — Project-Wide Test Suite")
    print("=" * 70)

    results: list[SuiteResult] = []
    for name, test_path, run_from in suites:
        print(f"\n--- {name} ---")
        result = _run_suite(name, test_path, run_from, fast=args.fast)
        results.append(result)

        if result.skipped:
            print(f"  SKIPPED: {result.skip_reason}")
        else:
            status = "PASSED" if result.passed else "FAILED"
            print(f"  {status} ({result.duration_seconds:.1f}s): {result.summary_line}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    ran = [r for r in results if not r.skipped]
    skipped = [r for r in results if r.skipped]
    failed = [r for r in ran if not r.passed]

    for r in ran:
        status = "PASS" if r.passed else "FAIL"
        print(f"  [{status}]  {r.name:30s} {r.summary_line}")
    for r in skipped:
        print(f"  [SKIP]  {r.name:30s} {r.skip_reason}")

    total_duration = sum(r.duration_seconds for r in ran)
    print(
        f"\n{len(ran) - len(failed)}/{len(ran)} suites passed"
        + (f", {len(skipped)} skipped" if skipped else "")
        + f" ({total_duration:.1f}s total)"
    )

    if failed:
        print(f"\nFAILED SUITES: {', '.join(r.name for r in failed)}")
        return 1

    print("\nAll suites passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
