#!/usr/bin/env python3
"""
Run every test suite in the right order, with the collision rules and
failure detection that otherwise have to be remembered by hand.

    python3 tests/run_all.py            # everything that runs locally
    python3 tests/run_all.py --testnet4 # + the two real-testnet4 Coldcard suites
    python3 tests/run_all.py --list     # show the plan and what would be skipped
    python3 tests/run_all.py --only unit,e2e

Encoded knowledge:
- "unit" and "comparison" may run in parallel (static server vs Pi node).
- "e2e" and "cc-sim" spawn a local bitcoind and must NOT overlap
  "comparison": a hiccup in the SSH tunnel while both run has let the local
  node grab port 18443 and fail the comparison suite with an auth error.
- The Coldcard suites share one simulator socket and switch its chain, so
  they run strictly sequentially; the testnet4 ones also spend (and return)
  the same WIF UTXOs.
- A suite's RESULTS line prints even after an uncaught exception aborts the
  run, so a green count alone proves nothing: a suite passes only if its
  exit code is 0, its output has a results line with 0 failures, and no
  Traceback appears anywhere.
"""
import argparse
import os
import re
import subprocess
import sys
import threading
import time

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_TEST_DIR)
_LOG_DIR = os.path.join(_TEST_DIR, "_logs")
NODE_ENV = os.path.join(_ROOT, "..", "prime", "ui-automation", "node-env.sh")

RESULTS_RE = re.compile(r"(?:RESULTS|Results):\s*(\d+) passed, (\d+) failed|^\s*(\d+) passed, (\d+) failed", re.M)


def has_testnet4_creds():
    return bool(os.environ.get("TESTNET4_WIF")) and bool(os.environ.get("TESTNET4_ADDRESS"))


def has_simulator():
    sys.path.insert(0, _TEST_DIR)
    try:
        import coldcard_sim
        return coldcard_sim.simulator_possible() or coldcard_sim.physical_forced()
    except Exception:
        return False


class Suite:
    def __init__(self, name, argv, skip_reason=None, timeout=1800, needs_results=True):
        self.name, self.argv, self.skip_reason, self.timeout = name, argv, skip_reason, timeout
        self.needs_results = needs_results  # decoder's node tests print no summary line
        self.passed = self.failed = None
        self.status = "pending"
        self.detail = ""
        self.seconds = 0.0

    def run(self):
        if self.skip_reason:
            self.status = "SKIP"
            self.detail = self.skip_reason
            return
        os.makedirs(_LOG_DIR, exist_ok=True)
        log_path = os.path.join(_LOG_DIR, f"{self.name}.log")
        t0 = time.time()
        try:
            with open(log_path, "w") as log:
                proc = subprocess.run(self.argv, cwd=_ROOT, stdout=log,
                                      stderr=subprocess.STDOUT, timeout=self.timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            self.status, self.detail = "FAIL", f"timed out after {self.timeout}s ({log_path})"
            self.seconds = time.time() - t0
            return
        self.seconds = time.time() - t0
        out = open(log_path).read()
        m = None
        for m in RESULTS_RE.finditer(out):
            pass  # keep the LAST results line
        if m:
            groups = [g for g in m.groups() if g is not None]
            self.passed, self.failed = int(groups[0]), int(groups[1])
        traceback = "Traceback (most recent call last)" in out
        results_ok = (m and self.failed == 0) or (not self.needs_results and not m)
        if rc == 0 and results_ok and not traceback:
            self.status = "PASS"
            self.detail = f"{self.passed} passed" if m else f"exit 0 ({out.count(chr(10))} lines)"
        else:
            self.status = "FAIL"
            why = []
            if rc != 0:
                why.append(f"exit {rc}")
            if not m and self.needs_results:
                why.append("no results line")
            elif self.failed:
                why.append(f"{self.failed} failed")
            if traceback:
                why.append("Traceback in output (a green count can mask an aborted run)")
            self.detail = ", ".join(why) + f" ({log_path})"


def build_plan(args):
    py = sys.executable

    def t(rel):
        return os.path.join("tests", rel)

    comparison_skip = None
    if not os.path.isfile(NODE_ENV):
        comparison_skip = f"node-env.sh not found at {NODE_ENV}"
    cc_skip = None if has_simulator() else \
        "no Coldcard simulator (set COLDCARD_FIRMWARE) and COLDCARD_PHYSICAL not set"
    t4_skip = cc_skip
    if t4_skip is None and not has_testnet4_creds():
        t4_skip = "TESTNET4_WIF / TESTNET4_ADDRESS not set"
    if t4_skip is None and not args.testnet4:
        t4_skip = "broadcasts on real testnet4; enable with --testnet4"
    decoder_dir = os.path.join(_ROOT, "psbt-decoder")
    decoder_skip = None if os.path.isfile(os.path.join(decoder_dir, "test", "test-psbt.js")) \
        else "psbt-decoder submodule not initialized (git submodule update --init)"

    suites = {
        "unit": Suite("unit", [py, t("test_psbt_builder.py")], timeout=900),
        "comparison": Suite("comparison", ["bash", NODE_ENV, "regtest", py, t("test_core_tx_comparison.py")],
                            skip_reason=comparison_skip, timeout=600),
        "decoder": Suite("decoder", ["bash", "-c",
                         "cd psbt-decoder && for f in test/test-*.js; do node $f || exit 1; done"],
                         skip_reason=decoder_skip, timeout=300, needs_results=False),
        "e2e": Suite("e2e", [py, t("test_regtest_e2e.py")], timeout=900),
        "cc-sim": Suite("cc-sim", [py, t("test_coldcard_simulation.py")], timeout=900),
        "cc-regtest": Suite("cc-regtest", [py, t("_test_coldcard_regtest.py")],
                            skip_reason=cc_skip, timeout=900),
        "cc-testnet4": Suite("cc-testnet4", [py, t("_test_coldcard_testnet4.py")],
                             skip_reason=t4_skip, timeout=1200),
        "cc-website": Suite("cc-website", [py, t("_test_coldcard_website_e2e.py")],
                            skip_reason=t4_skip, timeout=1800),
    }
    # (phase, [suite names]); suites inside a phase run in PARALLEL,
    # phases run in order. See the module docstring for why.
    phases = [
        ("parallel: static server + Pi node + node", ["unit", "comparison", "decoder"]),
        ("local bitcoind (after the Pi comparison)", ["e2e"]),
        ("local bitcoind", ["cc-sim"]),
        ("Coldcard simulator, sequential", ["cc-regtest"]),
        ("Coldcard simulator + real testnet4, sequential", ["cc-testnet4"]),
        ("Coldcard simulator + real testnet4, sequential", ["cc-website"]),
    ]
    if args.only:
        wanted = set(args.only.split(","))
        unknown = wanted - set(suites)
        if unknown:
            sys.exit(f"unknown suite(s): {', '.join(sorted(unknown))}; known: {', '.join(suites)}")
        for name, suite in suites.items():
            if name not in wanted and not suite.skip_reason:
                suite.skip_reason = "not selected via --only"
    return suites, phases


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--testnet4", action="store_true",
                    help="include the suites that broadcast on real testnet4 (funds return to the WIF)")
    ap.add_argument("--only", help="comma-separated suite names to run")
    ap.add_argument("--list", action="store_true", help="print the plan and exit")
    args = ap.parse_args()

    suites, phases = build_plan(args)
    if args.list:
        for phase_name, names in phases:
            for n in names:
                s = suites[n]
                print(f"  {n:12s} {'SKIP: ' + s.skip_reason if s.skip_reason else phase_name}")
        return

    t0 = time.time()
    for phase_name, names in phases:
        runnable = [suites[n] for n in names if not suites[n].skip_reason]
        for s in [suites[n] for n in names if suites[n].skip_reason]:
            s.run()
            print(f"  SKIP {s.name}: {s.detail}")
        if not runnable:
            continue
        print(f"== {phase_name}: {', '.join(s.name for s in runnable)}")
        threads = [threading.Thread(target=s.run) for s in runnable]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        for s in runnable:
            print(f"  {s.status} {s.name}: {s.detail} [{s.seconds:.0f}s]")

    print(f"\n{'=' * 64}")
    worst = 0
    for name, s in suites.items():
        mark = {"PASS": "✓", "FAIL": "✗", "SKIP": "-"}.get(s.status, "?")
        print(f"  {mark} {name:12s} {s.status:4s} {s.detail}")
        if s.status == "FAIL":
            worst = 1
    print(f"  total {time.time() - t0:.0f}s")
    print("=" * 64)
    sys.exit(worst)


if __name__ == "__main__":
    main()
