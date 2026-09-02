#!/usr/bin/env python3
"""
Connect-bridge test for Dustpan (formerly Bitcoin Address Sweeper).

Proves server/server.py's --connect mode can front a bitcoind it did NOT
spawn: a throwaway regtest node is started directly via the RegtestNode
class (bypassing server.py entirely), then server.py is started as a
separate subprocess in --connect mode pointed at that node's RPC endpoint.
Every bridge endpoint is exercised against real chain state created by
direct bitcoin-cli calls (never through the bridge -- the bridge has no
faucet in connect mode anyway), so a pass genuinely proves the bridge
against a node it doesn't own, not a self-fulfilling faucet flow.

Requires:
  - Bitcoin Core (bitcoind + bitcoin-cli) in PATH
  - Python Playwright: pip install playwright && playwright install chromium

Usage:
    python3 tests/test_connect_mode.py              # headless
    python3 tests/test_connect_mode.py --headed      # visible browser
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from playwright.sync_api import sync_playwright

# ============================================================
# Configuration
# ============================================================

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
HEADED = "--headed" in sys.argv

# Import RegtestNode directly, bypassing server.py's CLI entirely -- this is
# the "existing node we didn't spawn via the bridge" the --connect mode is
# meant to front.
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "server"))
import server as server_module  # noqa: E402  (needs the sys.path insert above)

FUND_AMOUNT = "0.25"       # BTC
FUND_SATS = 25_000_000     # sats


# ============================================================
# Test infrastructure (same pattern as test_regtest_e2e.py)
# ============================================================

_pass_count = 0
_fail_count = 0
_failures = []


def test(name, condition, detail=""):
    global _pass_count, _fail_count
    if condition:
        _pass_count += 1
        print(f"  ✓ {name}")
    else:
        _fail_count += 1
        msg = f"  ✗ {name}"
        if detail:
            msg += f"  — {detail}"
        print(msg)
        _failures.append(name)


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ============================================================
# Bridge subprocess lifecycle
# ============================================================

def start_bridge(port, rpc_port):
    """Start server.py <port> --connect 127.0.0.1:<rpc_port> as a subprocess
    (never as a Python import -- this exercises the real CLI path), wait for
    /api/health to report mode=connect."""
    proc = subprocess.Popen(
        [sys.executable, os.path.join(_PROJECT_ROOT, "server", "server.py"),
         str(port), "--connect", f"127.0.0.1:{rpc_port}",
         "--rpcuser", "test", "--rpcpassword", "test"],
        cwd=_PROJECT_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    for i in range(30):
        try:
            resp = urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2)
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "ok" and data.get("mode") == "connect":
                return proc, data
        except (URLError, ConnectionRefusedError, OSError):
            pass
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            raise RuntimeError(
                f"Bridge exited prematurely (rc={proc.returncode})\n{stderr}")
        time.sleep(1)
    proc.kill()
    raise RuntimeError("Bridge failed to become ready within 30s")


def stop_bridge(proc):
    """Gracefully stop the bridge. It owns no node, so this is pure process
    teardown -- SIGINT triggers the same KeyboardInterrupt shutdown path as
    --regtest, minus the RegtestNode.stop() call."""
    if not proc or proc.poll() is not None:
        return
    pgid = os.getpgid(proc.pid)
    try:
        os.kill(proc.pid, signal.SIGINT)
        proc.wait(timeout=10)
        print("  Bridge stopped gracefully.")
        return
    except (subprocess.TimeoutExpired, OSError):
        pass
    try:
        os.killpg(pgid, signal.SIGTERM)
        proc.wait(timeout=10)
        print("  Bridge process group terminated.")
        return
    except (subprocess.TimeoutExpired, OSError):
        pass
    try:
        os.killpg(pgid, signal.SIGKILL)
        proc.wait(timeout=5)
        print("  Bridge process group force-killed.")
    except (OSError, subprocess.TimeoutExpired):
        pass


def api_get_text(server_url, path, timeout=30):
    return urlopen(f"{server_url}{path}", timeout=timeout).read().decode("utf-8")


def api_get_json(server_url, path, timeout=30):
    return json.loads(api_get_text(server_url, path, timeout=timeout))


def api_post_raw_expect_status(server_url, path, body, timeout=30):
    """POST that may return a non-2xx status; urlopen raises HTTPError for
    those, so unwrap it into (status, body) like a normal response. Used for
    every POST here, including ones expected to succeed -- a bridge bug that
    turns a should-succeed call into a 4xx should show up as a failed
    assertion with the real error body, not an uncaught HTTPError that
    aborts the whole suite."""
    req = Request(f"{server_url}{path}", data=body.encode("utf-8"), method="POST")
    try:
        resp = urlopen(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


# ============================================================
# Tests
# ============================================================

def run_tests(page, base_url, server_url, node):
    """`node` is the directly-spawned RegtestNode -- used for every "ground
    truth" cli call (funding, mining, direct broadcast/sign) that must NOT
    go through the bridge, so a passing test proves the bridge against a
    node it doesn't own, not a self-fulfilling faucet loop."""

    # ========================================================
    section("1. Bridge Health")
    # ========================================================

    health = api_get_json(server_url, "/api/health")
    test("health status ok", health.get("status") == "ok", health)
    test("health mode is 'connect'", health.get("mode") == "connect", health)
    test("health chain is 'regtest'", health.get("chain") == "regtest", health)
    test("health 'regtest' back-compat bool is False (not a spawned node)",
         health.get("regtest") is False, health)
    test("health reports the bridged rpc_port",
         health.get("rpc_port") == node.rpc_port,
         f"expected {node.rpc_port}, got {health.get('rpc_port')}")
    test("health reports the bridged rpc_host",
         health.get("rpc_host") == "127.0.0.1", health)

    # ========================================================
    section("2. Tip Height")
    # ========================================================

    tip = int(api_get_text(server_url, "/api/blocks/tip/height").strip())
    direct_height = int(node._cli("getblockcount"))
    test("tip height matches the node's real height", tip == direct_height,
         f"bridge={tip} direct={direct_height}")

    # ========================================================
    section("3. Faucet-Funded Address -> /address/:addr/utxo")
    # ========================================================
    # Funding happens via DIRECT bitcoin-cli calls (RegtestNode.fund_address),
    # never through the bridge -- the bridge has no faucet in connect mode
    # (see section 8).

    addr = node._cli("getnewaddress", "", "bech32", wallet=node.wallet_name)
    test("address looks like regtest bech32", addr.startswith("bcrt1q"), addr)

    txid = node.fund_address(addr, FUND_AMOUNT)
    test("direct-cli fund txid looks valid",
         len(txid) == 64 and all(c in "0123456789abcdef" for c in txid), txid)

    utxos = api_get_json(server_url, f"/api/address/{addr}/utxo")
    test("bridge finds the funded UTXO via scantxoutset", len(utxos) == 1, utxos)
    # fund_address() funds via createrawtransaction + fundrawtransaction, and
    # fundrawtransaction places its change output at a RANDOM position -- the
    # payment to `addr` isn't reliably vout 0. Use the vout the bridge itself
    # reported (proven correct by the assertions below) for section 6's spend,
    # instead of assuming 0.
    fund_vout = utxos[0]["vout"] if utxos else 0
    if utxos:
        test("UTXO amount matches", utxos[0]["value"] == FUND_SATS,
             f"expected {FUND_SATS}, got {utxos[0].get('value')}")
        test("UTXO txid matches", utxos[0]["txid"] == txid, utxos[0])
        test("UTXO reported confirmed", utxos[0]["status"]["confirmed"] is True, utxos[0])

    # ========================================================
    section("4. Cache Behavior (60s TTL)")
    # ========================================================

    t0 = time.time()
    utxos_1st = api_get_json(server_url, f"/api/address/{addr}/utxo")
    t1 = time.time()
    utxos_2nd = api_get_json(server_url, f"/api/address/{addr}/utxo")
    t2 = time.time()
    test("cached second fetch returns the identical result",
         utxos_1st == utxos_2nd, f"{utxos_1st} vs {utxos_2nd}")
    # Regtest scans are already near-instant, so this isn't a strong timing
    # assertion by itself -- it's a sanity check that the cached path isn't
    # doing MORE work than the first call (a broken cache re-scanning every
    # time would tend to cost at least as much, not less).
    dt_first, dt_second = t1 - t0, t2 - t1
    test("cached second fetch is not slower than the first",
         dt_second <= dt_first + 0.5,
         f"first={dt_first:.3f}s second={dt_second:.3f}s")

    # ========================================================
    section("5. Raw Transaction Hex")
    # ========================================================

    tx_hex = api_get_text(server_url, f"/api/tx/{txid}/hex")
    direct_hex = node._cli("getrawtransaction", txid)
    test("bridge tx hex matches direct-cli tx hex", tx_hex.strip() == direct_hex.strip())

    bogus_txid = "ab" * 32
    try:
        urlopen(f"{server_url}/api/tx/{bogus_txid}/hex", timeout=10)
        test("unknown txid returns an error status", False, "expected HTTPError")
    except HTTPError as e:
        test("unknown txid returns an error status", e.code == 404, e.code)
        body = e.read().decode("utf-8", errors="replace")
        test("unknown txid error body is the node's own error message (passed through)",
             "transaction" in body.lower(), body)

    # ========================================================
    section("6. Broadcast via Bridge (POST /tx) + Direct Confirm")
    # ========================================================

    recipient = node._cli("getnewaddress", "", "bech32", wallet=node.wallet_name)
    # This spends the exact UTXO funded in section 3, so it's already fully
    # fundable without fundrawtransaction -- sign it directly.
    raw_hex = node._cli(
        "createrawtransaction",
        json.dumps([{"txid": txid, "vout": fund_vout}]),
        json.dumps([{recipient: 0.2495}]),  # leaves a 5,000-sat fee
        wallet=node.wallet_name)
    signed_json = node._cli("signrawtransactionwithwallet", raw_hex, wallet=node.wallet_name)
    signed = json.loads(signed_json)
    test("direct-cli sign complete", signed.get("complete") is True, signed)

    status, broadcast_txid = api_post_raw_expect_status(server_url, "/api/tx", signed["hex"])
    broadcast_txid = broadcast_txid.strip()
    test("bridge broadcast returns a valid txid",
         len(broadcast_txid) == 64 and all(c in "0123456789abcdef" for c in broadcast_txid),
         f"status={status} body={broadcast_txid}")

    # Connect mode must NOT auto-mine (that's a --regtest-spawn convenience
    # only) -- the tx should sit in the mempool until mined directly.
    mempool_entry = None
    if broadcast_txid and len(broadcast_txid) == 64:
        try:
            mempool_entry = node._cli_json("getmempoolentry", broadcast_txid)
        except Exception:
            mempool_entry = None
    test("connect-mode broadcast does NOT auto-mine (tx sits in the mempool)",
         mempool_entry is not None, mempool_entry)

    node.mine(1)
    decoded = node._cli_json("getrawtransaction", broadcast_txid, "true") if broadcast_txid else {}
    test("mined + confirmed after a direct-cli mine",
         decoded.get("confirmations", 0) >= 1, decoded)

    # ========================================================
    section("7. Fees Endpoint Shape")
    # ========================================================

    fees = api_get_json(server_url, "/api/v1/fees/recommended")
    for key in ("fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee"):
        test(f"fees response has '{key}'", key in fees, fees)
    # Regtest has no real fee market (estimatesmartfee always errors there),
    # so this falls back to the same flat 1 sat/vB used by --regtest/static.
    test("fees fall back to flat 1 sat/vB on regtest",
         all(fees.get(k) == 1 for k in ("fastestFee", "halfHourFee", "hourFee",
                                        "economyFee", "minimumFee")), fees)

    # ========================================================
    section("8. Faucet / Mine Refused in Connect Mode")
    # ========================================================

    f_status, f_body = api_post_raw_expect_status(
        server_url, "/api/faucet", json.dumps({"address": addr}))
    test("faucet refused in connect mode", f_status == 400, f"status={f_status} body={f_body}")
    test("faucet error explains why (requires --regtest)", "regtest" in f_body.lower(), f_body)

    m_status, m_body = api_post_raw_expect_status(
        server_url, "/api/mine", json.dumps({"blocks": 1}))
    test("mine refused in connect mode", m_status == 400, f"status={m_status} body={m_body}")
    test("mine error explains why (requires --regtest)", "regtest" in m_body.lower(), m_body)

    # ========================================================
    section("9. Browser: page against the bridge -- auto-select + UI fetch")
    # ========================================================

    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)
    page.wait_for_function("() => window._fn.networkDetected === true", timeout=15000)

    test("browser: serverMode true",
         page.evaluate("() => window._fn.serverMode") is True)
    test("browser: serverConnectMode true",
         page.evaluate("() => window._fn.serverConnectMode") is True)
    test("browser: network auto-selected to regtest (health chain=regtest)",
         page.evaluate("() => document.getElementById('network').value") == "regtest")

    # Fund a fresh address for the UI fetch, independent of the UTXO spent above.
    ui_addr = node._cli("getnewaddress", "", "bech32", wallet=node.wallet_name)
    ui_txid = node.fund_address(ui_addr, "0.1")
    test("UI-fetch address funded directly", len(ui_txid) == 64, ui_txid)

    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.fill("#fetchAddress", ui_addr)
    page.click("#fetchUtxosBtn")
    page.wait_for_function(
        "() => document.getElementById('fetchStatus').textContent.includes('Added')",
        timeout=15000)
    status_text = page.text_content("#fetchStatus")
    test("browser: UTXO fetched via the UI through the bridge", "Added 1 UTXO" in status_text,
         f"got: {status_text}")

    utxo_rows = page.query_selector_all("[data-utxo]")
    test("browser: 1 input row appears after the fetch", len(utxo_rows) == 1, len(utxo_rows))


# ============================================================
# Main
# ============================================================

def main():
    if not shutil.which("bitcoind") or not shutil.which("bitcoin-cli"):
        print("SKIP: bitcoind/bitcoin-cli not found in PATH.")
        print("Install Bitcoin Core to run the connect-bridge tests.")
        sys.exit(0)

    bridge_port = find_free_port()
    server_url = f"http://127.0.0.1:{bridge_port}"
    base_url = f"http://127.0.0.1:{bridge_port}/index.html"
    bridge_proc = None
    node = None

    print("Starting a direct (non-server.py-owned) regtest node, then "
          f"bridging it via server.py --connect on port {bridge_port}...")
    print(f"Mode: {'headed' if HEADED else 'headless'}\n")

    try:
        node = server_module.RegtestNode()
        node.start()
        print(f"  Direct regtest node up: rpc_port={node.rpc_port} datadir={node.datadir}")

        bridge_proc, health = start_bridge(bridge_port, node.rpc_port)
        print(f"  Bridge ready: {health}")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not HEADED)
            context = browser.new_context(accept_downloads=True)
            page = context.new_page()
            page.add_init_script("window.__TEST_MODE__ = true;")

            run_tests(page, base_url, server_url, node)

            browser.close()
    except Exception:
        traceback.print_exc()
    finally:
        if bridge_proc:
            print("\nStopping bridge...")
            stop_bridge(bridge_proc)
        if node:
            print("Stopping directly-spawned regtest node...")
            node.stop()

    # Summary
    print(f"\n{'='*60}")
    print(f"  RESULTS: {_pass_count} passed, {_fail_count} failed")
    print(f"{'='*60}")
    if _failures:
        print("\n  Failed tests:")
        for f in _failures:
            print(f"    ✗ {f}")
    print()

    sys.exit(1 if _fail_count > 0 else 0)


if __name__ == "__main__":
    main()
