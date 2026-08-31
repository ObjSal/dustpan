#!/usr/bin/env python3
"""
End-to-end test of the sweeper website with a real Coldcard MK4 on testnet4.

Tests the actual user flow through the Playwright browser:
1. Fetch UTXOs by WIF (hot wallet) and by address (Coldcard)
2. Enter HW wallet info (xfp, pubkey, path) for the CC UTXO
3. Set output to sweep all funds back to the WIF address
4. Create & Partially Sign PSBT (website signs WIF inputs)
5. Download PSBT, sign with Coldcard via ckcc CLI
6. Upload CC-signed PSBT back to the website
7. Combine & Finalize
8. Broadcast to testnet4
9. Verify tx in mempool and funds returned

Requires:
  - Coldcard MK4 plugged in, unlocked, set to XTN (testnet)
  - ckcc CLI: pip install ckcc-protocol
  - Playwright: pip install playwright && playwright install chromium
  - TESTNET4_WIF and TESTNET4_ADDRESS env vars set
"""

import http.server
import json
import os
import re
import socket
import subprocess
import coldcard_sim
import sys
import threading
import time
import traceback
from urllib.request import urlopen, Request

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_http_server(port):
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd

# Derivation path for the Coldcard input (BIP84, first receive address)
CC_PATH = "m/84'/1'/0'/0/0"
CC_ACCOUNT_PATH = "m/84h/1h/0h"   # ckcc xpub wants h-notation

MEMPOOL_API = "https://mempool.space/testnet4/api"


def pubkey_to_p2wpkh(pubkey_hex, network):
    """Derive P2WPKH (bech32) address from compressed pubkey hex."""
    from embit import ec as embit_ec, script as embit_script
    from embit.networks import NETWORKS
    pub = embit_ec.PublicKey.parse(bytes.fromhex(pubkey_hex))
    return embit_script.p2wpkh(pub).address(NETWORKS[network])


def detect_coldcard():
    """Auto-detect Coldcard device info via ckcc CLI.
    Returns (xfp, addr, pubkey, account_xpub) or raises RuntimeError.
    Uses ckcc xfp + ckcc pubkey + ckcc xpub only (no ckcc addr, which
    blocks the device waiting for user to dismiss the on-screen display).
    The account xpub is what the website is fed: a plain address cannot be
    given a key origin by hand any more, the xpub fetch supplies it."""
    result = subprocess.run(coldcard_sim.ckcc("xfp"), capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"ckcc xfp failed: {result.stderr.strip()}")
    xfp = result.stdout.strip()
    time.sleep(1)  # let Coldcard USB settle between commands

    result = subprocess.run(coldcard_sim.ckcc("pubkey", CC_PATH),
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"ckcc pubkey failed: {result.stderr.strip()}")
    pubkey = result.stdout.strip()

    # Derive address locally from pubkey (avoids ckcc addr which
    # shows address on Coldcard screen and blocks USB until dismissed)
    addr = pubkey_to_p2wpkh(pubkey, "test")
    time.sleep(1)

    result = subprocess.run(coldcard_sim.ckcc("xpub", CC_ACCOUNT_PATH),
                            capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"ckcc xpub failed: {result.stderr.strip()}")
    account_xpub = result.stdout.strip()

    return xfp, addr, pubkey, account_xpub

# ============================================================
# Test infra
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


def fetch_json(url):
    return json.loads(urlopen(url, timeout=30).read().decode())


# ============================================================
# Main
# ============================================================

def run_tests():
    from playwright.sync_api import sync_playwright

    wif_key = os.environ.get("TESTNET4_WIF")
    wif_address = os.environ.get("TESTNET4_ADDRESS")

    # ========================================================
    section("1. Preflight Checks")
    # ========================================================

    test("TESTNET4_WIF set", bool(wif_key))
    test("TESTNET4_ADDRESS set", bool(wif_address))
    if not wif_key or not wif_address:
        print("  ❌ Set TESTNET4_WIF and TESTNET4_ADDRESS env vars")
        return

    time.sleep(0.5)  # let USB settle
    coldcard_sim.start_simulator(chain="XTN")
    result = subprocess.run(coldcard_sim.ckcc("chain"), capture_output=True, text=True, timeout=30)
    test("Coldcard chain is XTN", result.stdout.strip() == "XTN")
    if result.stdout.strip() != "XTN":
        return

    # Auto-detect Coldcard device info
    print("  Auto-detecting Coldcard device info...")
    try:
        CC_XFP, CC_ADDR, CC_PUBKEY, CC_XPUB = detect_coldcard()
    except RuntimeError as e:
        test("ckcc can reach Coldcard", False, str(e))
        return

    print(f"  XFP:    {CC_XFP}")
    print(f"  CC addr:  {CC_ADDR}")
    print(f"  Pubkey: {CC_PUBKEY}")

    # Check both addresses have UTXOs
    if coldcard_sim.using_simulator():
        coldcard_sim.ensure_testnet4_funds(CC_ADDR, wif_key, wif_address, MEMPOOL_API)
    cc_utxos = fetch_json(f"{MEMPOOL_API}/address/{CC_ADDR}/utxo")
    wif_utxos = fetch_json(f"{MEMPOOL_API}/address/{wif_address}/utxo")
    test("CC has UTXOs on testnet4", len(cc_utxos) >= 1)
    test("WIF has UTXOs on testnet4", len(wif_utxos) >= 1)
    if not cc_utxos or not wif_utxos:
        print("  ❌ Both addresses need testnet4 UTXOs")
        return

    cc_sats = sum(u["value"] for u in cc_utxos)
    wif_sats = sum(u["value"] for u in wif_utxos)
    print(f"  CC balance:  {cc_sats} sats")
    print(f"  WIF balance: {wif_sats} sats")
    print(f"  Total:       {cc_sats + wif_sats} sats")

    # ========================================================
    section("2. Launch Browser & Fetch UTXOs")
    # ========================================================

    headed = "--headed" in sys.argv
    tmp_dir = os.path.join(_TEST_DIR, "_tmp_cc")
    os.makedirs(tmp_dir, exist_ok=True)

    # Start static HTTP server (ESM modules need http://, not file://)
    port = find_free_port()
    os.chdir(_PROJECT_ROOT)
    httpd = start_http_server(port)
    base_url = f"http://127.0.0.1:{port}/index.html"
    print(f"  Static server on port {port}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed)
        page = browser.new_page()

        # Enable test mode
        page.add_init_script("window.__TEST_MODE__ = true;")

        # Load page and wait for ESM modules to initialize
        page.goto(base_url)
        page.wait_for_function("() => window._fn !== undefined", timeout=15000)

        # Auto-accept dialogs (e.g. missing XFP warning)
        _dialogs = []
        page.on("dialog", lambda d: (_dialogs.append(d.message), d.accept()))

        # Select testnet4 (static server auto-selects testnet4, but be explicit)
        page.select_option("#network", "testnet")
        page.wait_for_timeout(500)

        # Fetch WIF UTXOs. mempool.space rate-limits after the funding/API
        # churn in section 1, so retry a couple of times (the page clears the
        # WIF from the input after each attempt).
        print("  Fetching WIF UTXOs...")
        for attempt in range(3):
            page.fill("#fetchAddress", wif_key)
            page.click("#fetchUtxosBtn")
            try:
                page.wait_for_selector("#utxoContainer [data-utxo]", timeout=40000)
                break
            except Exception:
                if attempt == 2:
                    raise
                print(f"  WIF fetch attempt {attempt + 1} empty "
                      f"({page.evaluate("() => document.getElementById('fetchStatus').textContent")!r}); retrying...")
                time.sleep(15)
        # WIF is cleared from input after fetch
        page.wait_for_timeout(1000)

        wif_utxo_count = page.locator("#utxoContainer [data-utxo]").count()
        test("WIF UTXOs fetched", wif_utxo_count >= 1, f"found {wif_utxo_count}")

        # Fetch CC UTXOs by the ACCOUNT XPUB. The website no longer lets a
        # plain address row be given HW info by hand (it cannot be done
        # correctly without the per-address pubkey); the HD import dialog
        # fills the path and pubkey for every imported address and the
        # fingerprint is typed once. The funded CC address is 0/0, so only
        # that address is selected -- nothing else touches mempool.space.
        print("  Importing CC UTXOs via the HD wallet dialog...")
        page.fill("#fetchAddress", CC_XPUB)
        page.click("#fetchUtxosBtn")
        page.wait_for_selector("#hdImportDialog", state="visible", timeout=10000)
        # tpub is ambiguous (Native SegWit or Taproot): pick Native SegWit
        if page.locator("#hdImportStepType").is_visible():
            page.click(".hd-type-card >> nth=0")
        page.wait_for_selector("#hdAddrList .hd-addr-row", timeout=5000)
        first_addr = page.locator("#hdAddrList .hd-addr").first.text_content()
        test("dialog: 0/0 matches the funded CC address", first_addr == CC_ADDR,
             f"dialog={first_addr} expected={CC_ADDR}")
        page.evaluate("""() => { const b = document.querySelectorAll('#hdAddrList input')[0];
            b.checked = true; b.dispatchEvent(new Event('change')); }""")
        page.click("#hdImportGo")
        page.wait_for_selector("#hdImportOverlay", state="hidden", timeout=60000)
        page.wait_for_timeout(500)

        total_utxo_count = page.locator("#utxoContainer [data-utxo]").count()
        cc_utxo_count = total_utxo_count - wif_utxo_count
        test("CC UTXOs fetched", cc_utxo_count >= 1,
             f"total={total_utxo_count}, wif={wif_utxo_count}, cc={cc_utxo_count}")

        # ========================================================
        section("3. Master fingerprint for the CC xpub source")
        # ========================================================

        # The xpub scan pre-filled path + pubkey on every CC row; the
        # fingerprint cannot be derived from an xpub, so it is typed once in
        # the source label and propagates to each row's .hw-xfp.
        xfp_label = page.locator("#utxoContainer .utxo-source-label[data-xpub-source] .xpub-xfp")
        test("CC xpub source label has a fingerprint field", xfp_label.count() >= 1)
        xfp_label.first.fill(CC_XFP)
        xfp_label.first.dispatch_event("input")
        page.wait_for_timeout(300)

        hw_set = page.evaluate("""() => {
            const rows = document.querySelectorAll('#utxoContainer [data-utxo]');
            let hwCount = 0;
            for (const row of rows) {
                if (row.getAttribute('data-wif')) continue;
                const xfp = row.querySelector('.hw-xfp');
                const path = row.querySelector('.hw-path');
                const pubkey = row.querySelector('.hw-pubkey');
                if (xfp && xfp.value && path && path.value && pubkey && pubkey.value) hwCount++;
            }
            return hwCount;
        }""")
        test("CC rows carry complete key origin (xfp + path + pubkey)", hw_set >= 1, f"hw_set={hw_set}")
        cc_pub_match = page.evaluate("""(pub) => {
            return Array.from(document.querySelectorAll('#utxoContainer [data-utxo]'))
                .some(r => !r.getAttribute('data-wif') && r.querySelector('.hw-pubkey') && r.querySelector('.hw-pubkey').value === pub);
        }""", CC_PUBKEY)
        test("xpub-derived pubkey matches ckcc pubkey for the funded path", cc_pub_match)
        # This suite drives the real UI: leave the software-signer claim OFF
        # so Create is only allowed because every input has a WIF or key origin.
        page.evaluate("() => { document.getElementById('softwareSignerOverride').checked = false; }")

        # ========================================================
        section("4. Configure Output & Create PSBT")
        # ========================================================

        # Wait for fee rates to load, set slow if needed
        page.wait_for_timeout(2000)
        fee_set = page.evaluate("""() => {
            const active = document.querySelector('.fee-preset.active');
            const feeVal = document.getElementById('feeRate').value;
            if (active || (feeVal && parseFloat(feeVal) > 0)) return true;
            // fallback: set 1 sat/vB manually
            document.getElementById('feeRate').value = '1';
            return true;
        }""")
        test("fee rate set", fee_set)

        # Set output to WIF address with wipe (sweep all)
        page.fill("#outputContainer [data-output] .output-address", wif_address)
        # Check wipe to sweep all
        wipe_checkbox = page.locator("#outputContainer [data-output] .output-wipe")
        if wipe_checkbox.count() > 0 and not wipe_checkbox.is_checked():
            wipe_checkbox.check()
        page.wait_for_timeout(300)

        # Clear tip to maximize returned funds
        page.evaluate("""() => {
            document.querySelectorAll('.tip-preset').forEach(p => p.classList.remove('active'));
            document.getElementById('tipSats').value = '0';
            if (window._fn && window._fn.updateTipSummary) window._fn.updateTipSummary();
            if (window._fn && window._fn.recalcWipeOutput) window._fn.recalcWipeOutput();
        }""")
        page.wait_for_timeout(300)

        # Mixed WIF + HW mode: WIF signing is deferred to the combine step,
        # so the button reads plain "Create PSBT".
        btn_text = page.locator("#createPsbt").inner_text()
        test("button says Create PSBT (mixed mode)", btn_text.strip() == "Create PSBT", f"got: '{btn_text}'")

        # Click Create (may fetch nonWitnessUtxo from mempool.space)
        print("  Creating PSBT...")
        page.click("#createPsbt")
        page.wait_for_timeout(3000)

        # Check PSBT was created
        psbt_visible = page.locator("#psbtResult").is_visible()
        test("PSBT result visible", psbt_visible)
        if not psbt_visible:
            # Check for alert
            print("  ❌ PSBT not created — dialogs seen:")
            for d in _dialogs:
                print(f"     - {d[:200]}")
            browser.close()
            return

        # Get PSBT hex (inside collapsed <details>, use textContent)
        psbt_hex = page.evaluate("() => document.getElementById('psbtHex').textContent")
        test("PSBT hex present", len(psbt_hex) > 100, f"len={len(psbt_hex)}")

        # Save PSBT to file for Coldcard signing
        psbt_bytes = bytes.fromhex(psbt_hex)
        psbt_in_path = os.path.join(tmp_dir, "website-mixed.psbt")
        psbt_out_path = os.path.join(tmp_dir, "website-mixed-signed.psbt")
        with open(psbt_in_path, "wb") as f:
            f.write(psbt_bytes)
        print(f"  PSBT saved: {psbt_in_path} ({len(psbt_bytes)} bytes)")

        # Verify PSBT has partial_sigs for WIF inputs
        has_partial = page.evaluate("""() => {
            const psbtBuf = window._Buffer.from(document.getElementById('psbtHex').textContent, 'hex');
            const psbt = window._bitcoin.Psbt.fromBuffer(psbtBuf);
            let partialCount = 0;
            for (const inp of psbt.data.inputs) {
                if (inp.partialSig && inp.partialSig.length > 0) partialCount++;
            }
            return { total: psbt.data.inputs.length, partial: partialCount };
        }""")
        # Deferred WIF signing: in mixed mode the created PSBT carries NO
        # signatures at all -- WIF inputs are signed in the browser at the
        # combine step, after the Coldcard returns its signature. (Pre-signed
        # WIF inputs used to trigger the Coldcard Q auto-finalize bug.)
        test("created PSBT is fully unsigned (WIF signing deferred)", has_partial["partial"] == 0,
             f"{has_partial['partial']}/{has_partial['total']} inputs have partial_sigs")
        test("PSBT has inputs for the CC to sign", has_partial["total"] >= 2,
             f"only {has_partial['total']} inputs")

        # ========================================================
        section("5. Sign with Coldcard")
        # ========================================================

        if os.path.exists(psbt_out_path):
            os.remove(psbt_out_path)

        print("  Sending PSBT to Coldcard for signing...")
        if coldcard_sim.using_simulator():
            print("  (simulator: approving automatically)")
        else:
            print("  >>> APPROVE THE TRANSACTION ON YOUR COLDCARD <<<")
        print()

        sign_result = coldcard_sim.sign_psbt(psbt_in_path, psbt_out_path)

        test("ckcc sign succeeded", sign_result.returncode == 0,
             f"stderr: {sign_result.stderr.strip()}")
        if sign_result.returncode != 0:
            browser.close()
            return

        test("signed file created", os.path.exists(psbt_out_path))

        # ========================================================
        section("6. Upload Signed PSBT & Combine")
        # ========================================================

        # Navigate to Sign/Combine step
        page.click("#nextToSign")
        page.wait_for_timeout(500)

        # Upload the CC-signed PSBT via file input
        file_input = page.locator("#psbtFiles")
        file_input.set_input_files(psbt_out_path)
        page.wait_for_timeout(1000)

        # Verify PSBT appeared in accumulator list
        psbt_items = page.locator(".psbt-list-item").count()
        test("signed PSBT in accumulator", psbt_items >= 1, f"found {psbt_items}")

        # Click Combine & Finalize
        print("  Combining & finalizing...")
        page.click("#combinePsbt")
        page.wait_for_timeout(2000)

        # Check we navigated to broadcast step
        broadcast_visible = page.locator("#cardBroadcast").is_visible()
        test("navigated to broadcast step", broadcast_visible)

        # Get the final tx hex
        final_hex = page.evaluate("""() => {
            const el = document.getElementById('combinedResult');
            return el ? el.textContent.trim() : '';
        }""")
        test("final tx hex present", len(final_hex) > 100, f"len={len(final_hex)}")

        if not final_hex:
            # Check for error
            combined_text = page.locator("#combinedResult").inner_text()
            print(f"  combinedResult: {combined_text[:200]}")
            browser.close()
            return

        # ========================================================
        section("7. Broadcast to Testnet4")
        # ========================================================

        # Click broadcast
        print("  Broadcasting to testnet4...")
        page.click("#broadcastTx")
        page.wait_for_timeout(5000)

        # Check broadcast result (format: "Broadcasted TXID:\n<txid>")
        broadcast_status = page.locator("#broadcastResult").inner_text()
        test("broadcast succeeded", "Broadcasted TXID" in broadcast_status or
             len(broadcast_status.strip()) == 64,
             f"status: {broadcast_status[:100]}")

        # Extract txid from broadcast result
        txid = ""
        match = re.search(r'[0-9a-f]{64}', broadcast_status)
        if match:
            txid = match.group(0)

        if txid:
            print(f"  TXID: {txid}")
            print(f"  https://mempool.space/testnet4/tx/{txid}")

            # Wait and verify
            print("  Waiting 5s for mempool propagation...")
            time.sleep(5)
            try:
                tx_data = fetch_json(f"{MEMPOOL_API}/tx/{txid}")
                test("tx visible in mempool", tx_data.get("txid") == txid)

                # Verify output goes to WIF address
                vouts = tx_data.get("vout", [])
                returned = any(v.get("scriptpubkey_address") == wif_address for v in vouts)
                test("funds returned to WIF address", returned)
                if returned:
                    returned_amount = sum(v["value"] for v in vouts
                                          if v.get("scriptpubkey_address") == wif_address)
                    print(f"  Returned: {returned_amount} sats to {wif_address}")
            except Exception as e:
                test("tx verification", False, str(e))

            print(f"\n  ✅ FULL E2E SUCCESS — website + Coldcard + testnet4!")
        else:
            test("txid extracted", False, f"status: {broadcast_status[:200]}")

        browser.close()

    # Clean up
    httpd.shutdown()
    for f_name in ["website-mixed.psbt", "website-mixed-signed.psbt"]:
        f_path = os.path.join(tmp_dir, f_name)
        if os.path.exists(f_path):
            os.remove(f_path)


# ============================================================
# Entry
# ============================================================

def main():
    print("=" * 60)
    print("  Website + Coldcard E2E Test (Testnet4)")
    print("  (Real browser + real device + real broadcast)")
    print("=" * 60)

    run_tests()

    print(f"\n{'='*60}")
    print(f"  Results: {_pass_count} passed, {_fail_count} failed")
    print(f"{'='*60}")
    if _failures:
        print(f"\n  Failed tests:")
        for f in _failures:
            print(f"    ✗ {f}")
    print()

    sys.exit(1 if _fail_count > 0 else 0)


if __name__ == "__main__":
    main()
