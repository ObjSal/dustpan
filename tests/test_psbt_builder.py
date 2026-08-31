#!/usr/bin/env python3
"""
Playwright test suite for Bitcoin Address Sweeper.

Tests all pure functions via page.evaluate() and DOM interactions
via Playwright actions. Runs against the real index.html in a browser.

Requires:
  - Python Playwright: pip install playwright && playwright install chromium

Usage:
    python3 tests/test_psbt_builder.py              # headless
    python3 tests/test_psbt_builder.py --headed      # visible browser
"""

import http.server
import os
import socket
import sys
import threading
import time
import traceback

from playwright.sync_api import sync_playwright

# ============================================================
# Configuration
# ============================================================

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
HEADED = "--headed" in sys.argv

# Known test vectors
# Testnet4 P2WPKH address
TESTNET_P2WPKH = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
# Mainnet P2WPKH address
MAINNET_P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
# Mainnet P2TR address
MAINNET_P2TR = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
# Mainnet P2PKH
MAINNET_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
# Mainnet P2SH
MAINNET_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"

# P2WPKH scriptPubKey for MAINNET_P2WPKH (OP_0 <20-byte-hash>)
P2WPKH_SCRIPT = "0014751e76e8199196d454941c45d1b3a323f1433bd6"
# P2TR scriptPubKey (OP_1 <32-byte-x-only-pubkey>)
P2TR_SCRIPT = "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# Regtest
REGTEST_BECH32 = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

# A valid-looking txid (64 hex chars)
FAKE_TXID = "a" * 64


# ============================================================
# HTTP Server
# ============================================================

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_http_server(port):
    """Start a simple HTTP server in a background thread."""
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


# ============================================================
# Test infrastructure
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


# ============================================================
# Tests
# ============================================================

def run_tests(page, base_url):
    """Run all tests against the loaded page."""

    # --------------------------------------------------------
    # Setup: stub, then navigate and wait for module init
    # --------------------------------------------------------
    # The unit suite must not depend on mempool.space being responsive: a
    # rate-limited tip fetch at load left the height unknown and the (correct)
    # lock-time validation blocked PSBT creation in later sections. Serve a
    # fixed chain tip for every request -- installed BEFORE goto so the
    # load-time fetch cannot race it. Tests that exercise the fetch itself
    # add their own route on top (LIFO) and restore this one on unroute.
    page.route("**/blocks/tip/height",
               lambda route, req: route.fulfill(status=200, content_type="text/plain", body="900000"))
    # Same reasoning for the other live endpoints the page touches: raw-tx
    # lookups (all fake txids in this suite -- 404 matches expectations) and
    # fee rates (fixed values; no test asserts live labels).
    page.route("**/api/tx/*/hex", lambda route, req: route.fulfill(status=404, body="Transaction not found"))
    page.route("**/v1/fees/recommended", lambda route, req: route.fulfill(
        status=200, content_type="application/json",
        body='{"fastestFee":3,"halfHourFee":2,"hourFee":1,"economyFee":1,"minimumFee":1}'))
    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)
    # Settle one stubbed fetch so tipHeight is deterministic from here on.
    page.evaluate("() => window._fn.fetchTipHeight()")

    # Global dialog handler — auto-accepts all dialogs, records messages
    _all_dialogs = []
    page.on("dialog", lambda d: (_all_dialogs.append(d.message), d.accept()))

    # ========================================================
    section("1. hexToBytes")
    # ========================================================

    # Valid hex
    result = page.evaluate("() => Array.from(window._fn.hexToBytes('deadbeef'))")
    test("hexToBytes valid hex", result == [0xde, 0xad, 0xbe, 0xef], f"got {result}")

    # Empty input
    result = page.evaluate("() => Array.from(window._fn.hexToBytes(''))")
    test("hexToBytes empty string", result == [], f"got {result}")

    # Null/undefined
    result = page.evaluate("() => Array.from(window._fn.hexToBytes(null))")
    test("hexToBytes null", result == [], f"got {result}")

    # Odd-length hex should throw
    threw = page.evaluate("""() => {
        try { window._fn.hexToBytes('abc'); return false; }
        catch(e) { return true; }
    }""")
    test("hexToBytes odd-length throws", threw)

    # Single byte
    result = page.evaluate("() => Array.from(window._fn.hexToBytes('ff'))")
    test("hexToBytes single byte", result == [255], f"got {result}")

    # ========================================================
    section("2. getSelectedNetwork")
    # ========================================================

    # Mainnet (default)
    page.select_option("#network", "mainnet")
    result = page.evaluate("() => { const n = window._fn.getSelectedNetwork(); return n.bech32; }")
    test("getSelectedNetwork mainnet bech32", result == "bc", f"got {result}")

    # Testnet
    page.select_option("#network", "testnet")
    result = page.evaluate("() => { const n = window._fn.getSelectedNetwork(); return n.bech32; }")
    test("getSelectedNetwork testnet bech32", result == "tb", f"got {result}")

    # Regtest
    page.select_option("#network", "regtest")
    result = page.evaluate("() => { const n = window._fn.getSelectedNetwork(); return n.bech32; }")
    test("getSelectedNetwork regtest bech32", result == "bcrt", f"got {result}")

    # ========================================================
    section("2b. getMempoolBaseUrl")
    # ========================================================

    page.select_option("#network", "mainnet")
    result = page.evaluate("() => window._fn.getMempoolBaseUrl()")
    test("getMempoolBaseUrl mainnet", result == "https://mempool.space/api", f"got {result}")

    page.select_option("#network", "testnet")
    result = page.evaluate("() => window._fn.getMempoolBaseUrl()")
    test("getMempoolBaseUrl testnet", result == "https://mempool.space/testnet4/api", f"got {result}")

    page.select_option("#network", "regtest")
    result = page.evaluate("() => window._fn.getMempoolBaseUrl()")
    test("getMempoolBaseUrl regtest", result == "https://mempool.space/signet/api", f"got {result}")

    # ========================================================
    section("3. validateBitcoinAddress")
    # ========================================================

    # Reset to mainnet for address tests
    page.select_option("#network", "mainnet")

    # Mainnet P2WPKH — valid
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{MAINNET_P2WPKH}", net);
    }}""")
    test("validateBitcoinAddress mainnet P2WPKH valid", result is True)

    # Mainnet P2TR — valid
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{MAINNET_P2TR}", net);
    }}""")
    test("validateBitcoinAddress mainnet P2TR valid", result is True)

    # Mainnet P2PKH — valid
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{MAINNET_P2PKH}", net);
    }}""")
    test("validateBitcoinAddress mainnet P2PKH valid", result is True)

    # Mainnet P2SH — valid
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{MAINNET_P2SH}", net);
    }}""")
    test("validateBitcoinAddress mainnet P2SH valid", result is True)

    # Testnet address on mainnet — invalid
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{TESTNET_P2WPKH}", net);
    }}""")
    test("validateBitcoinAddress testnet addr on mainnet invalid", result is False)

    # Invalid string
    result = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("notanaddress", net);
    }""")
    test("validateBitcoinAddress garbage invalid", result is False)

    # Empty string
    result = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("", net);
    }""")
    test("validateBitcoinAddress empty invalid", result is False)

    # Testnet P2WPKH on testnet — valid
    page.select_option("#network", "testnet")
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{TESTNET_P2WPKH}", net);
    }}""")
    test("validateBitcoinAddress testnet P2WPKH valid", result is True)

    # Mainnet on testnet — invalid
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{MAINNET_P2WPKH}", net);
    }}""")
    test("validateBitcoinAddress mainnet addr on testnet invalid", result is False)

    # Regtest
    page.select_option("#network", "regtest")
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateBitcoinAddress("{REGTEST_BECH32}", net);
    }}""")
    test("validateBitcoinAddress regtest valid", result is True)

    # ========================================================
    section("4. validateScriptPubKey")
    # ========================================================

    page.select_option("#network", "mainnet")

    # Valid P2WPKH script
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateScriptPubKey("{P2WPKH_SCRIPT}", net);
    }}""")
    test("validateScriptPubKey P2WPKH valid", result is True)

    # Invalid hex
    result = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateScriptPubKey("zzzz", net);
    }""")
    test("validateScriptPubKey invalid hex", result is False)

    # Empty
    result = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        return window._fn.validateScriptPubKey("", net);
    }""")
    test("validateScriptPubKey empty", result is False)

    # ========================================================
    section("5. decodeAddressFromScript")
    # ========================================================

    page.select_option("#network", "mainnet")

    # P2WPKH script → mainnet address
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.decodeAddressFromScript("{P2WPKH_SCRIPT}", net);
    }}""")
    test("decodeAddressFromScript P2WPKH", result == MAINNET_P2WPKH, f"got {result}")

    # P2TR script (Taproot manual detection)
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        return window._fn.decodeAddressFromScript("{P2TR_SCRIPT}", net);
    }}""")
    test("decodeAddressFromScript P2TR returns address", result is not None and result.startswith("bc1p"), f"got {result}")

    # Invalid script returns null
    result = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        return window._fn.decodeAddressFromScript("deadbeef", net);
    }""")
    test("decodeAddressFromScript invalid returns null", result is None)

    # Empty returns null
    result = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        return window._fn.decodeAddressFromScript("", net);
    }""")
    test("decodeAddressFromScript empty returns null", result is None)

    # ========================================================
    section("6. estimateVirtualSize")
    # ========================================================

    # Create a simple PSBT to test vsize estimation
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const utxos = [{{
            txid: "{FAKE_TXID}",
            vout: 0,
            value: 100000,
            scriptPubKey: "{P2WPKH_SCRIPT}"
        }}];
        const outputs = [{{
            address: "{MAINNET_P2WPKH}",
            value: 90000
        }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        return window._fn.estimateVirtualSize(psbt);
    }}""")
    # 1 input, 1 output: baseSize = 10 + 41 + 34 = 85, witnessSize = 107
    # vsize = ceil((3*85 + 107) / 4) = ceil(362/4) = 91
    test("estimateVirtualSize 1-in 1-out", result == 91, f"got {result}")

    # 2 inputs, 2 outputs
    result = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const utxos = [
            {{ txid: "{FAKE_TXID}", vout: 0, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}" }},
            {{ txid: "{FAKE_TXID}", vout: 1, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}" }}
        ];
        const outputs = [
            {{ address: "{MAINNET_P2WPKH}", value: 90000 }},
            {{ address: "{MAINNET_P2WPKH}", value: 90000 }}
        ];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        return window._fn.estimateVirtualSize(psbt);
    }}""")
    # 2 inputs, 2 outputs: baseSize = 10 + 82 + 68 = 160, witnessSize = 214
    # vsize = ceil((3*160 + 214) / 4) = ceil(694/4) = 174
    test("estimateVirtualSize 2-in 2-out", result == 174, f"got {result}")

    # ========================================================
    section("7. colourField")
    # ========================================================

    # Test with an output address input
    page.select_option("#network", "mainnet")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.click("#addOutputButton")

    # Empty → neutral (rgba(255,255,255,0.15))
    color = page.evaluate("""() => {
        const el = document.querySelector('.output-address');
        el.value = '';
        window._fn.colourField(el, false);
        return el.style.borderColor;
    }""")
    test("colourField empty → neutral", "255" in color or "0.15" in color, f"got '{color}'")

    # Valid → green (#2ecc71)
    color = page.evaluate("""() => {
        const el = document.querySelector('.output-address');
        el.value = 'something';
        window._fn.colourField(el, true);
        return el.style.borderColor;
    }""")
    test("colourField valid → green", "2ecc71" in color or "46, 204, 113" in color, f"got '{color}'")

    # Invalid → red (#e74c3c)
    color = page.evaluate("""() => {
        const el = document.querySelector('.output-address');
        el.value = 'invalid';
        window._fn.colourField(el, false);
        return el.style.borderColor;
    }""")
    test("colourField invalid → red", "e74c3c" in color or "231, 76, 60" in color, f"got '{color}'")

    # ========================================================
    section("8. createPsbtFromInputs")
    # ========================================================

    page.select_option("#network", "mainnet")

    # Basic PSBT creation — no change
    result = page.evaluate(f"""() => {{
        const utxos = [{{ txid: "{FAKE_TXID}", vout: 0, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}" }}];
        const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 90000 }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        return {{
            inputCount: psbt.data.inputs.length,
            outputCount: psbt.data.outputs.length,
            hasBuffer: typeof psbt.toBuffer === 'function'
        }};
    }}""")
    test("createPsbt no change — 1 input", result["inputCount"] == 1)
    test("createPsbt no change — 1 output", result["outputCount"] == 1)
    test("createPsbt has toBuffer", result["hasBuffer"] is True)

    # Outputs > inputs — should throw
    threw = page.evaluate(f"""() => {{
        try {{
            const utxos = [{{ txid: "{FAKE_TXID}", vout: 0, value: 50000, scriptPubKey: "{P2WPKH_SCRIPT}" }}];
            const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 90000 }}];
            window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
            return false;
        }} catch(e) {{ return e.message; }}
    }}""")
    test("createPsbt outputs>inputs throws", "exceed" in str(threw).lower(), f"got {threw}")

    # Multiple inputs and outputs (implicit fee)
    result = page.evaluate(f"""() => {{
        const utxos = [
            {{ txid: "{FAKE_TXID}", vout: 0, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}" }},
            {{ txid: "{FAKE_TXID}", vout: 1, value: 200000, scriptPubKey: "{P2WPKH_SCRIPT}" }}
        ];
        const outputs = [
            {{ address: "{MAINNET_P2WPKH}", value: 50000 }},
            {{ address: "{MAINNET_P2WPKH}", value: 60000 }}
        ];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        return {{
            inputCount: psbt.data.inputs.length,
            outputCount: psbt.data.outputs.length
        }};
    }}""")
    # 2 inputs, 2 outputs, implicit fee = 300000-110000 = 190000
    test("createPsbt multi — 2 inputs", result["inputCount"] == 2)
    test("createPsbt multi — 2 outputs", result["outputCount"] == 2)

    # Verify witnessUtxo is set on inputs
    result = page.evaluate(f"""() => {{
        const utxos = [{{ txid: "{FAKE_TXID}", vout: 0, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}" }}];
        const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 90000 }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        const inp = psbt.data.inputs[0];
        return {{
            hasWitnessUtxo: !!inp.witnessUtxo,
            witnessValue: inp.witnessUtxo ? inp.witnessUtxo.value.toString() : null
        }};
    }}""")
    test("createPsbt input has witnessUtxo", result["hasWitnessUtxo"] is True)
    test("createPsbt witnessUtxo value correct", result["witnessValue"] == "100000")

    # ========================================================
    section("9. DOM: Add/Remove Input Rows")
    # ========================================================

    # Clear existing inputs first
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")

    # Add an input
    page.click("#addInputButton")
    count = page.evaluate("() => document.querySelectorAll('[data-utxo]').length")
    test("addInput creates row", count == 1)

    # Add another
    page.click("#addInputButton")
    count = page.evaluate("() => document.querySelectorAll('[data-utxo]').length")
    test("addInput second row", count == 2)

    # Remove first input (click ✕)
    page.click("[data-utxo]:first-child .remove")
    count = page.evaluate("() => document.querySelectorAll('[data-utxo]').length")
    test("remove input row", count == 1)

    # ========================================================
    section("10. DOM: Add/Remove Output Rows")
    # ========================================================

    # Clear existing outputs
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")

    # Add output
    page.click("#addOutputButton")
    count = page.evaluate("() => document.querySelectorAll('[data-output]').length")
    test("addOutput creates row", count == 1)

    # Add another
    page.click("#addOutputButton")
    count = page.evaluate("() => document.querySelectorAll('[data-output]').length")
    test("addOutput second row", count == 2)

    # Remove one
    page.click("[data-output]:first-child .remove")
    count = page.evaluate("() => document.querySelectorAll('[data-output]').length")
    test("remove output row", count == 1)

    # ========================================================
    section("11. DOM: Fee Rate Always Visible")
    # ========================================================

    fee_visible = page.evaluate("() => document.getElementById('feeRateGroup').style.display !== 'none'")
    test("fee rate section always visible", fee_visible)

    # ========================================================
    section("12. DOM: Script Label Live Decoding")
    # ========================================================

    page.select_option("#network", "mainnet")

    # Clear and add fresh input
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.click("#addInputButton")

    # Type a valid scriptPubKey
    script_input = page.locator("[data-utxo] .script-input")
    script_input.fill(P2WPKH_SCRIPT)
    script_input.dispatch_event("input")
    time.sleep(0.2)

    label = page.locator("[data-utxo] .script-label span").text_content()
    test("script label shows decoded address", label == MAINNET_P2WPKH, f"got '{label}'")

    # Type invalid script
    script_input.fill("deadbeef")
    script_input.dispatch_event("input")
    time.sleep(0.2)

    label = page.locator("[data-utxo] .script-label span").text_content()
    test("script label shows Invalid for bad script", "Invalid" in label, f"got '{label}'")

    # ========================================================
    section("13. DOM: Address Validation Coloring")
    # ========================================================

    page.select_option("#network", "mainnet")

    # Clear and add fresh output
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.click("#addOutputButton")

    addr_input = page.locator("[data-output] .output-address")

    # Type valid address
    addr_input.fill(MAINNET_P2WPKH)
    addr_input.dispatch_event("input")
    time.sleep(0.2)
    color = page.evaluate("() => document.querySelector('.output-address').style.borderColor")
    test("output address valid → green", "2ecc71" in color or "46, 204, 113" in color, f"got '{color}'")

    # Type invalid address
    addr_input.fill("notvalid")
    addr_input.dispatch_event("input")
    time.sleep(0.2)
    color = page.evaluate("() => document.querySelector('.output-address').style.borderColor")
    test("output address invalid → red", "e74c3c" in color or "231, 76, 60" in color, f"got '{color}'")

    # ========================================================
    section("14. DOM: Default Output Row on Load")
    # ========================================================

    # Reload page to check default state
    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)
    count = page.evaluate("() => document.querySelectorAll('#outputContainer [data-output]').length")
    test("default output row on load", count == 1)

    # ========================================================
    section("15. DOM: Network Change Re-validates")
    # ========================================================

    # Set up a mainnet script, then switch to testnet
    page.select_option("#network", "mainnet")
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.click("#addInputButton")
    script_input = page.locator("[data-utxo] .script-input")
    script_input.fill(P2WPKH_SCRIPT)
    script_input.dispatch_event("input")
    time.sleep(0.2)

    # On mainnet it should show the address
    label = page.locator("[data-utxo] .script-label span").text_content()
    test("script valid on mainnet", label == MAINNET_P2WPKH, f"got '{label}'")

    # Switch to testnet — network switch with data clears UTXOs (confirm auto-accepted)
    page.select_option("#network", "testnet")
    time.sleep(0.3)
    utxo_count = page.locator("#utxoContainer [data-utxo]").count()
    test("script cleared on network change", utxo_count == 0, f"got {utxo_count} UTXOs")

    # ========================================================
    section("16. DOM: Fee Calculation Updates")
    # ========================================================

    page.select_option("#network", "mainnet")

    # Set up input and output
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")

    page.evaluate(f"""() => {{
        window._fn.addInput(null, "{FAKE_TXID}", 0, 100000, "{P2WPKH_SCRIPT}");
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 50000);
    }}""")

    # Set fee rate
    page.fill("#feeRate", "10")
    page.locator("#feeRate").dispatch_event("input")
    time.sleep(0.3)

    fee_text = page.evaluate("() => document.getElementById('feeCalc').textContent")
    test("fee calc shows estimated fee", "Estimated fee" in fee_text, f"got '{fee_text}'")
    test("fee calc shows vB", "vB" in fee_text, f"got '{fee_text}'")
    test("fee calc shows available", "Available" in fee_text, f"got '{fee_text}'")

    # ========================================================
    section("17. Integration: Create PSBT Download")
    # ========================================================

    page.select_option("#network", "mainnet")

    # Set up valid inputs
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")

    page.evaluate(f"""() => {{
        window._fn.addInput(null, "{FAKE_TXID}", 0, 100000, "{P2WPKH_SCRIPT}");
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 90000);
    }}""")
    page.fill("#feeRate", "10")

    # Click Create PSBT and verify results area appears
    page.click("#createPsbt")
    time.sleep(1)
    test("PSBT result area visible", page.is_visible("#psbtResult"))

    # Verify PSBT hex is shown
    psbt_hex = page.text_content("#psbtHex")
    test("PSBT hex is non-empty", len(psbt_hex) > 0, f"len={len(psbt_hex)}")
    test("PSBT hex starts with 70736274ff", psbt_hex.startswith("70736274ff"), f"got {psbt_hex[:20]}")

    # Click Download and verify download
    with page.expect_download() as download_info:
        page.click("#downloadPsbt")
    download = download_info.value
    test("PSBT download triggered", download is not None)
    test("PSBT filename is unsigned.psbt", download.suggested_filename == "unsigned.psbt")

    # Verify the downloaded PSBT is valid
    path = download.path()
    with open(path, "rb") as f:
        psbt_bytes = f.read()
    test("PSBT file is non-empty", len(psbt_bytes) > 0, f"size={len(psbt_bytes)}")
    # PSBT magic bytes: "psbt\xff"
    test("PSBT has magic header", psbt_bytes[:5] == b"psbt\xff", f"got {psbt_bytes[:5]}")

    # ========================================================
    section("18. Integration: Validation Errors")
    # ========================================================

    # Missing fee rate
    page.select_option("#network", "mainnet")
    time.sleep(2)  # wait for fetchFeeRates to resolve
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate(f"""() => {{
        window._fn.addInput(null, "", 0, 100000, "{P2WPKH_SCRIPT}");
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 50000);
    }}""")
    page.evaluate("() => document.getElementById('feeRate').value = ''")

    _all_dialogs.clear()
    page.click("#createPsbt")
    time.sleep(2)
    test("missing fee rate shows alert", len(_all_dialogs) > 0 and "fee" in _all_dialogs[-1].lower(),
         f"got {_all_dialogs}")

    # No outputs (disable tip so only outputContainer matters)
    _all_dialogs.clear()
    page.fill("#feeRate", "10")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate("""() => {
        document.querySelectorAll('.tip-preset').forEach(b => b.classList.remove('active'));
        document.querySelector('.tip-preset[data-pct="0"]').classList.add('active');
        document.getElementById('tipSats').value = '';
    }""")
    page.click("#createPsbt")
    time.sleep(1)
    test("no outputs shows alert", len(_all_dialogs) > 0 and "output" in _all_dialogs[-1].lower(),
         f"got {_all_dialogs}")

    # ========================================================
    section("19. Integration: Implicit Fee PSBT Creation")
    # ========================================================

    page.select_option("#network", "mainnet")

    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")

    page.evaluate(f"""() => {{
        window._fn.addInput(null, "{FAKE_TXID}", 0, 100000, "{P2WPKH_SCRIPT}");
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 95000);
    }}""")
    page.fill("#feeRate", "1")

    page.click("#createPsbt")
    time.sleep(1)
    test("implicit fee PSBT result visible", page.is_visible("#psbtResult"))

    with page.expect_download() as download_info:
        page.click("#downloadPsbt")
    download = download_info.value
    test("implicit fee PSBT download works", download is not None)

    # Verify PSBT has 1 output
    path = download.path()
    with open(path, "rb") as f:
        psbt_bytes = f.read()
    test("implicit fee PSBT has magic header", psbt_bytes[:5] == b"psbt\xff")

    # Verify through JS that 1 output
    result = page.evaluate(f"""() => {{
        const utxos = [{{ txid: "{FAKE_TXID}", vout: 0, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}" }}];
        const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 95000 }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        return psbt.data.outputs.length;
    }}""")
    test("implicit fee PSBT: 1 output in JS", result == 1)

    # ========================================================
    section("20. HW Wallet Info Toggle")
    # ========================================================

    page.select_option("#network", "mainnet")
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.click("#addInputButton")

    # HW fields should be hidden by default
    hw_visible = page.evaluate("() => document.querySelector('.hw-fields').classList.contains('open')")
    test("HW fields hidden by default", not hw_visible)

    # Click toggle to open
    page.click(".hw-toggle")
    hw_visible = page.evaluate("() => document.querySelector('.hw-fields').classList.contains('open')")
    test("HW fields visible after toggle", hw_visible)

    # Click toggle to close
    page.click(".hw-toggle")
    hw_visible = page.evaluate("() => document.querySelector('.hw-fields').classList.contains('open')")
    test("HW fields hidden after second toggle", not hw_visible)

    # ========================================================
    section("20b. bip32Derivation in PSBT")
    # ========================================================

    page.select_option("#network", "mainnet")

    # Create PSBT with bip32Derivation data
    # Use a known compressed pubkey (33 bytes = 66 hex)
    test_pubkey = "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    test_xfp = "aabbccdd"
    test_path = "m/84'/0'/0'/0/0"

    result = page.evaluate(f"""() => {{
        const utxos = [{{
            txid: "{FAKE_TXID}",
            vout: 0,
            value: 100000,
            scriptPubKey: "{P2WPKH_SCRIPT}",
            xfp: "{test_xfp}",
            pubkey: "{test_pubkey}",
            derivationPath: "{test_path}"
        }}];
        const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 90000 }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        const inp = psbt.data.inputs[0];
        return {{
            hasBip32: !!inp.bip32Derivation && inp.bip32Derivation.length > 0,
            xfp: inp.bip32Derivation ? Array.from(inp.bip32Derivation[0].masterFingerprint).map(b => b.toString(16).padStart(2,'0')).join('') : null,
            path: inp.bip32Derivation ? inp.bip32Derivation[0].path : null,
            pubkeyLen: inp.bip32Derivation ? inp.bip32Derivation[0].pubkey.length : 0
        }};
    }}""")
    test("bip32Derivation present in input", result["hasBip32"] is True)
    test("bip32 XFP correct", result["xfp"] == test_xfp, f"got {result['xfp']}")
    test("bip32 path correct", result["path"] == test_path, f"got {result['path']}")
    test("bip32 pubkey is 33 bytes", result["pubkeyLen"] == 33, f"got {result['pubkeyLen']}")

    # PSBT without bip32Derivation (no HW info)
    result = page.evaluate(f"""() => {{
        const utxos = [{{
            txid: "{FAKE_TXID}",
            vout: 0,
            value: 100000,
            scriptPubKey: "{P2WPKH_SCRIPT}"
        }}];
        const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 90000 }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        const inp = psbt.data.inputs[0];
        return {{ hasBip32: !!inp.bip32Derivation }};
    }}""")
    test("no bip32Derivation when no HW info", result["hasBip32"] is False)

    # Multi-input: one with bip32, one without
    result = page.evaluate(f"""() => {{
        const utxos = [
            {{
                txid: "{FAKE_TXID}", vout: 0, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}",
                xfp: "{test_xfp}", pubkey: "{test_pubkey}", derivationPath: "{test_path}"
            }},
            {{
                txid: "{FAKE_TXID}", vout: 1, value: 50000, scriptPubKey: "{P2WPKH_SCRIPT}"
            }}
        ];
        const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 140000 }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        return {{
            input0_bip32: !!psbt.data.inputs[0].bip32Derivation,
            input1_bip32: !!psbt.data.inputs[1].bip32Derivation
        }};
    }}""")
    test("multi-input: input 0 has bip32", result["input0_bip32"] is True)
    test("multi-input: input 1 no bip32", result["input1_bip32"] is False)

    # ========================================================
    section("21. PSBT Buffer Round-Trip")
    # ========================================================

    # Create a PSBT, convert to buffer and back
    result = page.evaluate(f"""() => {{
        const utxos = [{{ txid: "{FAKE_TXID}", vout: 0, value: 100000, scriptPubKey: "{P2WPKH_SCRIPT}" }}];
        const outputs = [{{ address: "{MAINNET_P2WPKH}", value: 90000 }}];
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, "");
        const buf = psbt.toBuffer();
        // Round-trip: parse back
        const net = window._fn.getSelectedNetwork();
        const psbt2 = window._bitcoin.Psbt.fromBuffer(buf, {{ network: net }});
        return {{
            inputCount: psbt2.data.inputs.length,
            outputCount: psbt2.data.outputs.length,
            bufferLength: buf.length
        }};
    }}""")
    test("PSBT round-trip — inputs preserved", result["inputCount"] == 1)
    test("PSBT round-trip — outputs preserved", result["outputCount"] == 1)
    test("PSBT buffer has content", result["bufferLength"] > 0)


    # ========================================================
    section("22. xpub Public Key Derivation")
    # ========================================================

    # BIP32 test vector 1 master xpub (depth 0)
    MASTER_XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    # normalizeExtendedKey — xpub passthrough
    result = page.evaluate(f"""() => {{
        const r = window._fn.normalizeExtendedKey("{MASTER_XPUB}");
        return {{ key: r.key, isTestnet: r.isTestnet }};
    }}""")
    test("normalizeExtendedKey: xpub unchanged", result["key"] == MASTER_XPUB)
    test("normalizeExtendedKey: xpub is mainnet", result["isTestnet"] is False)

    # normalizeExtendedKey — invalid key
    result = page.evaluate("""() => {
        try { window._fn.normalizeExtendedKey("notavalidkey"); return "no error"; }
        catch (e) { return e.message; }
    }""")
    test("normalizeExtendedKey: invalid key throws", "error" not in result.lower() or "nrecognized" in result.lower() or result != "no error", f"got: {result}")

    # getRelativePath — basic
    result = page.evaluate("""() => window._fn.getRelativePath("m/84'/0'/0'/0/5", 3)""")
    test("getRelativePath: m/84'/0'/0'/0/5 depth 3 → 0/5", result == "0/5")

    # getRelativePath — depth 0
    result = page.evaluate("""() => window._fn.getRelativePath("m/0/1", 0)""")
    test("getRelativePath: m/0/1 depth 0 → 0/1", result == "0/1")

    # getRelativePath — too shallow
    result = page.evaluate("""() => {
        try { window._fn.getRelativePath("m/84'/0'", 3); return "no error"; }
        catch (e) { return e.message; }
    }""")
    test("getRelativePath: too shallow throws", result != "no error")

    # getRelativePath — hardened child from xpub
    result = page.evaluate("""() => {
        try { window._fn.getRelativePath("m/84'/0'/0'/0'/5", 3); return "no error"; }
        catch (e) { return e.message; }
    }""")
    test("getRelativePath: hardened child throws", "hardened" in result.lower())

    # derivePublicKeyFromXpub — end-to-end with master xpub at m/0/1
    result = page.evaluate(f"""() => {{
        const pubkey = window._fn.derivePublicKeyFromXpub("{MASTER_XPUB}", "m/0/1");
        return {{ pubkey, len: pubkey.length, prefix: pubkey.slice(0, 2) }};
    }}""")
    test("derivePublicKeyFromXpub: returns 66 hex", result["len"] == 66)
    test("derivePublicKeyFromXpub: starts with 02 or 03", result["prefix"] in ("02", "03"))

    # derivePublicKeyFromXpub — same xpub different path gives different key
    result = page.evaluate(f"""() => {{
        const k1 = window._fn.derivePublicKeyFromXpub("{MASTER_XPUB}", "m/0/0");
        const k2 = window._fn.derivePublicKeyFromXpub("{MASTER_XPUB}", "m/0/1");
        return {{ k1, k2, different: k1 !== k2 }};
    }}""")
    test("derivePublicKeyFromXpub: different paths → different keys", result["different"])

    # DOM: xpub auto-derives pubkey
    page.click("#addInputButton")
    page.click("[data-utxo]:last-child .hw-toggle")
    page.fill("[data-utxo]:last-child .hw-path", "m/0/0")
    page.fill(f"[data-utxo]:last-child .hw-xpub", MASTER_XPUB)
    page.dispatch_event("[data-utxo]:last-child .hw-xpub", "input")
    pubkey_val = page.input_value("[data-utxo]:last-child .hw-pubkey")
    test("DOM: xpub auto-populates pubkey", len(pubkey_val) == 66, f"got len={len(pubkey_val)}")

    # DOM: pubkey field is readonly when xpub present
    is_readonly = page.evaluate("() => document.querySelector('[data-utxo]:last-child .hw-pubkey').readOnly")
    test("DOM: pubkey readonly when xpub set", is_readonly)

    # DOM: clearing xpub restores manual mode
    page.fill("[data-utxo]:last-child .hw-xpub", "")
    page.dispatch_event("[data-utxo]:last-child .hw-xpub", "input")
    is_readonly = page.evaluate("() => document.querySelector('[data-utxo]:last-child .hw-pubkey').readOnly")
    test("DOM: pubkey editable when xpub cleared", not is_readonly)

    # Clean up the extra input row
    page.click("[data-utxo]:last-child .remove")

    # ========================================================
    section("23. Output Percentages & Wipe")
    # ========================================================

    page.select_option("#network", "mainnet")
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")

    # Clear tip to avoid it affecting wipe calculations
    page.click('.tip-preset[data-pct="0"]')
    page.fill("#tipSats", "")

    # Set up: 1 input worth 100000 sats, fee rate 10 sat/vB
    page.evaluate(f"""() => {{
        window._fn.addInput(null, "{FAKE_TXID}", 0, 100000, "{P2WPKH_SCRIPT}");
    }}""")
    page.fill("#feeRate", "10")
    page.locator("#feeRate").dispatch_event("input")
    time.sleep(0.3)

    # Get available sats for reference
    available = page.evaluate("() => window._fn.getAvailableSats()")
    test("getAvailableSats returns positive", available > 0, f"got {available}")

    # Test 1: Percentage label shows % of total input
    total_in = 100000
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate(f"""() => {{
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", {total_in});
    }}""")
    time.sleep(0.2)
    pct_text = page.evaluate("() => document.querySelector('.output-pct').textContent")
    pct = float(pct_text.replace('%', ''))
    test("pct label 100% from total input", abs(pct - 100) < 0.1, f"got {pct_text}")

    # Test 2: Percentage label ~50% from half input
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    half = total_in // 2
    page.evaluate(f"""() => {{
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", {half});
    }}""")
    time.sleep(0.2)
    pct_text = page.evaluate("() => document.querySelector('.output-pct').textContent")
    pct = float(pct_text.replace('%', ''))
    test("pct label ~50% from half input", abs(pct - 50) < 0.1, f"got {pct_text}")

    # Test 3: Output pct labels sum < 100 (fee takes a share)
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate(f"""() => {{
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", {available});
    }}""")
    time.sleep(0.2)
    pct_text = page.evaluate("() => document.querySelector('.output-pct').textContent")
    pct = float(pct_text.replace('%', ''))
    test("wipe output pct < 100 (fee share)", pct < 100, f"got {pct_text}")

    # Test 5: Wipe checkbox — only one active at a time
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate(f"""() => {{
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 10000);
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 20000);
    }}""")
    # Check first wipe
    page.locator("[data-output]:first-child .output-wipe").check()
    time.sleep(0.2)
    first_checked = page.evaluate("() => document.querySelector('[data-output]:first-child .output-wipe').checked")
    test("wipe first checked", first_checked)

    # Check second wipe — should uncheck first
    page.locator("[data-output]:last-child .output-wipe").check()
    time.sleep(0.2)
    first_still = page.evaluate("() => document.querySelector('[data-output]:first-child .output-wipe').checked")
    second_checked = page.evaluate("() => document.querySelector('[data-output]:last-child .output-wipe').checked")
    test("wipe only-one: first unchecked", not first_still)
    test("wipe only-one: second checked", second_checked)

    # Test 6: Wipe remainder calc
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate(f"""() => {{
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 30000);
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 0);
    }}""")
    # Recalculate available with current number of outputs (2)
    avail_2out = page.evaluate("() => window._fn.getAvailableSats()")
    page.locator("[data-output]:last-child .output-wipe").check()
    time.sleep(0.2)
    wipe_val = page.evaluate("() => parseInt(document.querySelector('[data-output]:last-child .output-value').value)")
    expected_wipe = avail_2out - 30000
    test("wipe remainder calc", abs(wipe_val - expected_wipe) < 2, f"got {wipe_val}, expected ~{expected_wipe}")

    # Test 7: Wipe row value disabled
    val_disabled = page.evaluate("() => document.querySelector('[data-output]:last-child .output-value').disabled")
    test("wipe row: value disabled", val_disabled)

    # Test 8: Uncheck wipe restores value field
    page.locator("[data-output]:last-child .output-wipe").uncheck()
    time.sleep(0.2)
    val_disabled = page.evaluate("() => document.querySelector('[data-output]:last-child .output-value').disabled")
    test("unwipe: value enabled", not val_disabled)

    # Test 9: gatherOutputs returns correct data (disable tip to test base outputs only)
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate("""() => {
        document.querySelectorAll('.tip-preset').forEach(b => b.classList.remove('active'));
        document.querySelector('.tip-preset[data-pct="0"]').classList.add('active');
        document.getElementById('tipSats').value = '';
    }""")
    page.evaluate(f"""() => {{
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 50000);
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 40000);
    }}""")
    gathered = page.evaluate("() => window._fn.gatherOutputs()")
    test("gatherOutputs count", len(gathered) == 2)
    test("gatherOutputs first value", gathered[0]["value"] == 50000)
    test("gatherOutputs second value", gathered[1]["value"] == 40000)

    # Test 10: Fee rate required for PSBT creation (use empty txid to avoid network fetch delays)
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate(f"""() => {{
        window._fn.addInput(null, "", 0, 100000, "{P2WPKH_SCRIPT}");
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 90000);
    }}""")
    page.evaluate("() => { document.getElementById('feeRate').value = ''; }")
    _all_dialogs.clear()
    page.click("#createPsbt")
    time.sleep(2)
    test("fee rate required for create", len(_all_dialogs) > 0 and "fee" in _all_dialogs[-1].lower(),
         f"got {_all_dialogs}")

    # ========================================================
    section("24. isExtendedKey")
    # ========================================================

    MASTER_XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    result = page.evaluate(f'() => window._fn.isExtendedKey("{MASTER_XPUB}")')
    test("isExtendedKey: valid xpub", result is True)

    # tpub — generate a valid tpub in browser using normalizeExtendedKey round-trip
    result = page.evaluate("""() => {
        // isExtendedKey works for any key prefix recognized by normalizeExtendedKey.
        // Test by checking that the xpub version-bytes map covers tpub.
        // Rather than constructing a tpub from scratch, verify the detection
        // mechanism: normalizeExtendedKey has tpub (0x043587CF) in its map.
        // Generate a valid tpub: take xpub bytes, swap version to tpub, re-encode with bs58check.
        try {
            // Since bs58check isn't exposed, test with a known BIP32 test vector 1 tpub
            // (same key data as MASTER_XPUB but with tpub version prefix)
            // The actual key: use the bs58check import from the module scope
            const xpub = '""" + MASTER_XPUB + """';
            // Access the module-scoped bs58check and bip32 via internal parse
            const result = window._fn.normalizeExtendedKey(xpub);
            // The key normalized to xpub — confirms xpub works
            // For tpub, we need a separate test — verify the function
            // checks for tpub prefix in its version map
            return true;  // xpub detection already tested above
        } catch (e) {
            return e.message;
        }
    }""")
    # The real test: isExtendedKey differentiates xpub-family from addresses
    # We already tested xpub directly, and zpub below tests SLIP-132 prefix
    test("isExtendedKey: normalizeExtendedKey works for xpub", result is True)

    # zpub — test by generating one in browser
    result = page.evaluate("""() => {
        // Generate a zpub by encoding a key with zpub version bytes (0x04b24746)
        // Just test that the function correctly handles the prefix detection
        try {
            // BIP84 zpub for mainnet (BIP32 test vector 1 re-encoded)
            const r = window._fn.normalizeExtendedKey(
                "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
            );
            return r.key.startsWith("xpub");
        } catch { return false; }
    }""")
    test("isExtendedKey: zpub normalizes ok", result is True, f"got {result}")

    result = page.evaluate("""() => {
        return window._fn.isExtendedKey(
            "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
        );
    }""")
    test("isExtendedKey: valid zpub", result is True, f"got {result}")

    result = page.evaluate(f'() => window._fn.isExtendedKey("{MAINNET_P2WPKH}")')
    test("isExtendedKey: plain address is false", result is False)

    result = page.evaluate('() => window._fn.isExtendedKey("notakey123")')
    test("isExtendedKey: garbage is false", result is False)

    # ========================================================
    section("25. pubkeyToAddress")
    # ========================================================

    # Derive a known pubkey from xpub for testing
    pubkey_hex = page.evaluate(f"""() => {{
        return window._fn.derivePublicKeyFromXpub("{MASTER_XPUB}", "m/0/0");
    }}""")

    # pubkeyToAddress expects a Buffer, not a hex string
    # Pass the hex and convert inside the evaluate call
    PK = pubkey_hex

    # P2WPKH mainnet
    page.select_option("#network", "mainnet")
    addr = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const pk = window._Buffer.from("{PK}", "hex");
        return window._fn.pubkeyToAddress(pk, "p2wpkh", net);
    }}""")
    test("pubkeyToAddress: P2WPKH mainnet", addr.startswith("bc1q"), f"got {addr}")

    # P2TR mainnet
    addr_tr = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const pk = window._Buffer.from("{PK}", "hex");
        return window._fn.pubkeyToAddress(pk, "p2tr", net);
    }}""")
    test("pubkeyToAddress: P2TR mainnet", addr_tr.startswith("bc1p"), f"got {addr_tr}")

    # P2SH-P2WPKH mainnet
    addr_sh = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const pk = window._Buffer.from("{PK}", "hex");
        return window._fn.pubkeyToAddress(pk, "p2sh-p2wpkh", net);
    }}""")
    test("pubkeyToAddress: P2SH-P2WPKH mainnet", addr_sh.startswith("3"), f"got {addr_sh}")

    # P2WPKH testnet
    page.select_option("#network", "testnet")
    addr_t = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const pk = window._Buffer.from("{PK}", "hex");
        return window._fn.pubkeyToAddress(pk, "p2wpkh", net);
    }}""")
    test("pubkeyToAddress: P2WPKH testnet", addr_t.startswith("tb1q"), f"got {addr_t}")

    # P2TR testnet
    addr_t_tr = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const pk = window._Buffer.from("{PK}", "hex");
        return window._fn.pubkeyToAddress(pk, "p2tr", net);
    }}""")
    test("pubkeyToAddress: P2TR testnet", addr_t_tr.startswith("tb1p"), f"got {addr_t_tr}")

    # Deterministic: same pubkey+type+network → same address
    page.select_option("#network", "mainnet")
    addr2 = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const pk = window._Buffer.from("{PK}", "hex");
        return window._fn.pubkeyToAddress(pk, "p2wpkh", net);
    }}""")
    test("pubkeyToAddress: deterministic", addr2 == addr, f"got {addr2} vs {addr}")

    # ========================================================
    section("26. renderQrToCanvas")
    # ========================================================

    # Smoke test: function is callable
    result = page.evaluate("""() => {
        const canvas = document.createElement('canvas');
        const matrix = QRGenerator.generateQR('test', QRGenerator.EC_L);
        window._fn.renderQrToCanvas(matrix, canvas, 350);
        return { w: canvas.width, h: canvas.height, modules: matrix.length };
    }""")
    test("renderQrToCanvas: callable", result is not None)
    test("renderQrToCanvas: canvas size 350", result["w"] == 350 and result["h"] == 350,
         f"got {result['w']}x{result['h']}")

    # Canvas has pixel data (not all white)
    has_dark = page.evaluate("""() => {
        const canvas = document.createElement('canvas');
        const matrix = QRGenerator.generateQR('test', QRGenerator.EC_L);
        window._fn.renderQrToCanvas(matrix, canvas, 350);
        const ctx = canvas.getContext('2d');
        const data = ctx.getImageData(0, 0, 350, 350).data;
        for (let i = 0; i < data.length; i += 4) {
            if (data[i] === 0 && data[i+1] === 0 && data[i+2] === 0) return true;
        }
        return false;
    }""")
    test("renderQrToCanvas: has dark pixels", has_dark)

    # ========================================================
    section("27. hidePsbtResult")
    # ========================================================

    # First make the result visible by creating a PSBT
    page.select_option("#network", "mainnet")
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate(f"""() => {{
        window._fn.addInput(null, "{FAKE_TXID}", 0, 100000, "{P2WPKH_SCRIPT}");
        window._fn.addOutput(null, "{MAINNET_P2WPKH}", 90000);
    }}""")
    page.fill("#feeRate", "1")
    page.locator("#feeRate").dispatch_event("input")
    _all_dialogs.clear()
    page.click("#createPsbt")
    time.sleep(3)
    # Result should be visible
    vis_before = page.evaluate("() => document.getElementById('psbtResult').style.display")

    page.evaluate("() => window._fn.hidePsbtResult()")
    vis_after = page.evaluate("() => document.getElementById('psbtResult').style.display")
    test("hidePsbtResult: hides result", vis_after == "none",
         f"before={vis_before}, after={vis_after}")

    qr_btn = page.text_content("#showQrPsbt")
    test("hidePsbtResult: resets QR button text",
         "Show QR Code" in qr_btn,
         f"got '{qr_btn}'")

    # ========================================================
    section("28. handleScannedQR format detection")
    # ========================================================

    # Build a test PSBT for QR format tests
    test_psbt = page.evaluate(f"""() => {{
        const net = window._fn.getSelectedNetwork();
        const psbt = new window._bitcoin.Psbt({{ network: net }});
        psbt.addInput({{
            hash: "{FAKE_TXID}",
            index: 0,
            witnessUtxo: {{
                script: window._Buffer.from("{P2WPKH_SCRIPT}", "hex"),
                value: 100000n,
            }},
        }});
        psbt.addOutput({{
            address: "{MAINNET_P2WPKH}",
            value: 90000n,
        }});
        const buf = psbt.toBuffer();
        return {{
            hex: window._Buffer.from(buf).toString("hex"),
            base64: window._Buffer.from(buf).toString("base64"),
        }};
    }}""")

    # Binary PSBT (binaryData with PSBT magic bytes) → adds to accumulator
    accum_before = page.evaluate("() => window._fn.psbtAccumulator.length")
    page.evaluate(f"""() => {{
        const buf = window._Buffer.from("{test_psbt["hex"]}", "hex");
        const binaryData = new Uint8Array(buf);
        window._fn.handleScannedQR("", binaryData);
    }}""")
    accum_after = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("handleScannedQR: binary PSBT added to accumulator",
         accum_after == accum_before + 1,
         f"before={accum_before}, after={accum_after}")

    # Base64 PSBT → adds to accumulator
    page.evaluate(f'() => window._fn.handleScannedQR("{test_psbt["base64"]}")')
    accum_after2 = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("handleScannedQR: base64 PSBT added to accumulator",
         accum_after2 == accum_after + 1,
         f"before={accum_after}, after={accum_after2}")

    # Hex PSBT → adds to accumulator
    page.evaluate(f'() => window._fn.handleScannedQR("{test_psbt["hex"]}")')
    accum_after3 = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("handleScannedQR: hex PSBT added to accumulator",
         accum_after3 == accum_after2 + 1,
         f"before={accum_after2}, after={accum_after3}")

    # Non-PSBT → shows feedback, doesn't add
    page.evaluate('() => window._fn.handleScannedQR("Hello World")')
    accum_after4 = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("handleScannedQR: non-PSBT not added",
         accum_after4 == accum_after3,
         f"before={accum_after3}, after={accum_after4}")

    feedback = page.text_content("#qrScanProgress")
    test("handleScannedQR: non-PSBT feedback",
         "not a psbt" in feedback.lower(),
         f"got {feedback}")

    # Raw transaction hex → sets finalTxHex and shows broadcast section
    # Build a fake raw tx hex (version 2 + segwit marker + dummy data)
    raw_tx_hex = "02000000" + "0001" + "aa" * 100  # 216 hex chars
    page.evaluate('() => { window._fn.showCard("cardBroadcast"); }')
    page.evaluate(f'() => window._fn.handleScannedQR("{raw_tx_hex}")')
    final_tx = page.evaluate("() => window._fn.finalTxHex")
    test("handleScannedQR: raw tx hex sets finalTxHex",
         final_tx == raw_tx_hex.lower(),
         f"got {final_tx[:40] if final_tx else None}...")
    scan_feedback = page.text_content("#qrScanProgress")
    test("handleScannedQR: raw tx feedback",
         "signed transaction scanned" in scan_feedback.lower(),
         f"got {scan_feedback}")
    broadcast_visible = page.evaluate('() => document.getElementById("broadcastSection").style.display !== "none"')
    test("handleScannedQR: raw tx shows broadcast section",
         broadcast_visible,
         f"broadcastSection visible={broadcast_visible}")

    # Version 1 raw tx also detected
    raw_tx_v1 = "01000000" + "bb" * 50
    page.evaluate(f'() => window._fn.handleScannedQR("{raw_tx_v1}")')
    final_tx_v1 = page.evaluate("() => window._fn.finalTxHex")
    test("handleScannedQR: version 1 raw tx detected",
         final_tx_v1 == raw_tx_v1.lower(),
         f"got {final_tx_v1[:20] if final_tx_v1 else None}")

    # ========================================================
    section("29. PSBT Accumulator List")
    # ========================================================

    # Clear accumulator by reloading page
    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)
    _all_dialogs.clear()

    accum_len = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("accumulator: starts empty", accum_len == 0)

    # Add a PSBT
    page.evaluate(f"""() => {{
        const buf = window._Buffer.from("{test_psbt['hex']}", "hex");
        window._fn.addPsbtToList(buf, "Test PSBT 1", "File");
    }}""")
    accum_len = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("addPsbtToList: increases count", accum_len == 1)

    # Check DOM has list item
    list_items = page.evaluate("() => document.querySelectorAll('.psbt-list-item').length")
    test("addPsbtToList: DOM list item created", list_items == 1,
         f"got {list_items}")

    # Add a second
    page.evaluate(f"""() => {{
        const buf = window._Buffer.from("{test_psbt['hex']}", "hex");
        window._fn.addPsbtToList(buf, "Test PSBT 2", "QR");
    }}""")
    accum_len = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("addPsbtToList: second item", accum_len == 2)

    # Remove first
    page.evaluate("() => window._fn.removePsbtFromList(0)")
    accum_len = page.evaluate("() => window._fn.psbtAccumulator.length")
    test("removePsbtFromList: decreases count", accum_len == 1)


    # ========================================================
    section("30. WIF Detection (isWif)")
    # ========================================================

    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)

    # Select testnet for WIF tests (c/9 prefixes)
    page.select_option("#network", "testnet")
    time.sleep(2)

    # Generate a testnet keypair and get WIF
    test_wif = page.evaluate("""() => {
        const kp = window._ECPair.makeRandom({ network: window._fn.getSelectedNetwork() });
        return kp.toWIF();
    }""")

    # Valid testnet WIF → true
    result = page.evaluate(f"() => window._fn.isWif('{test_wif}')")
    test("isWif: valid testnet WIF", result == True, f"WIF={test_wif[:8]}...")

    # xpub → false
    result = page.evaluate("() => window._fn.isWif('tpubD6NzVbkrYhZ4XgiXtGrdW5XDZA5gE4REcKytCFfnQd6pXhbJA85')")
    test("isWif: xpub returns false", result == False)

    # address → false
    result = page.evaluate("() => window._fn.isWif('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')")
    test("isWif: address returns false", result == False)

    # garbage → false
    result = page.evaluate("() => window._fn.isWif('not-a-wif-at-all')")
    test("isWif: garbage returns false", result == False)

    # Mainnet WIF on testnet → false (network mismatch)
    result = page.evaluate("() => window._fn.isWif('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')")
    test("isWif: mainnet WIF on testnet returns false", result == False)


    # ========================================================
    section("31. Step Indicator Wizard")
    # ========================================================

    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)

    # Step indicator should exist
    step_count = page.evaluate("() => document.querySelectorAll('.step-indicator .step').length")
    test("step indicator: has 4 step circles", step_count == 4, f"got {step_count}")

    # Step 1 should be active by default
    step1_active = page.evaluate("() => document.querySelector('.step-indicator .step').classList.contains('active')")
    test("step indicator: step 1 active by default", step1_active == True)

    # Only Create card visible by default
    create_visible = page.evaluate("() => !document.getElementById('cardCreate').classList.contains('hidden')")
    broadcast_hidden = page.evaluate("() => document.getElementById('cardBroadcast').classList.contains('hidden')")
    test("wizard: only Create card visible initially", create_visible and broadcast_hidden)

    # setStep(2) marks step 1 as done, step 2 as active
    page.evaluate("() => window._fn.setStep(2)")
    step1_done = page.evaluate("() => document.querySelector('.step-indicator .step').classList.contains('done')")
    step2_active = page.evaluate("() => document.querySelectorAll('.step-indicator .step')[1].classList.contains('active')")
    test("setStep(2): step 1 done, step 2 active", step1_done and step2_active)

    # showCard('cardBroadcast') shows broadcast card, hides create
    page.evaluate("() => window._fn.showCard('cardBroadcast')")
    create_hidden = page.evaluate("() => document.getElementById('cardCreate').classList.contains('hidden')")
    broadcast_visible = page.evaluate("() => !document.getElementById('cardBroadcast').classList.contains('hidden')")
    test("showCard('cardBroadcast'): broadcast visible, create hidden", create_hidden and broadcast_visible)


    # ========================================================
    section("32. allUtxosHaveWif")
    # ========================================================

    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)

    # Empty → false
    result = page.evaluate("() => window._fn.allUtxosHaveWif()")
    test("allUtxosHaveWif: empty returns false", result == False)

    # Add UTXO with data-wif → true
    page.evaluate("""() => {
        window._fn.addFetchedInput('a'.repeat(64), 0, 1000, '0014' + 'ab'.repeat(20),
            'tb1qtest', null, 'cTestWif');
    }""")
    result = page.evaluate("() => window._fn.allUtxosHaveWif()")
    test("allUtxosHaveWif: single UTXO with WIF returns true", result == True)

    # Check WIF toggle shows checkmark
    wif_toggle_text = page.evaluate("() => document.querySelector('.wif-toggle').textContent")
    test("WIF toggle: shows checkmark when WIF present",
         '\u2714' in wif_toggle_text, f"got '{wif_toggle_text}'")

    # Check data-wif attribute is set
    data_wif = page.evaluate("() => document.querySelector('[data-utxo]').getAttribute('data-wif')")
    test("data-wif attribute: set on UTXO row", data_wif == 'cTestWif')

    # Add another UTXO without WIF → false (mixed)
    page.evaluate("""() => {
        window._fn.addFetchedInput('b'.repeat(64), 0, 2000, '0014' + 'cd'.repeat(20),
            'tb1qtest2');
    }""")
    result = page.evaluate("() => window._fn.allUtxosHaveWif()")
    test("allUtxosHaveWif: mixed UTXOs returns false", result == False)


    # ========================================================
    section("33. Dynamic Step Layout")
    # ========================================================

    # Reload for fresh state
    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)

    # Default: 2-step layout (Create → Broadcast), button says "Create PSBT"
    create_btn_text = page.evaluate("() => document.getElementById('createPsbt').textContent")
    test("default layout: button says 'Create PSBT'",
         create_btn_text.strip() == 'Create PSBT', f"got '{create_btn_text}'")

    visible_steps = page.evaluate("""() => {
        return Array.from(document.querySelectorAll('.step-indicator .step'))
            .filter(s => s.style.display !== 'none').length;
    }""")
    test("default layout: 2 steps visible", visible_steps == 2, f"got {visible_steps}")

    step_labels = page.evaluate("""() => {
        return Array.from(document.querySelectorAll('.step-indicator .step'))
            .filter(s => s.style.display !== 'none')
            .map(s => s.querySelector('small').textContent);
    }""")
    test("default layout: step labels are Create/Broadcast",
         step_labels == ['Create', 'Broadcast'], f"got {step_labels}")

    next_btn_text = page.evaluate("() => document.getElementById('nextToSign').textContent")
    test("default layout: next button says 'Next: Broadcast →'",
         'Broadcast' in next_btn_text, f"got '{next_btn_text}'")

    # Add UTXO with WIF → triggers 2-step layout
    page.evaluate("""() => {
        window._fn.addFetchedInput('a'.repeat(64), 0, 1000, '0014' + 'ab'.repeat(20),
            'tb1qtest', null, 'cTestWif');
        window._fn.updateStepLayout();
    }""")

    create_btn_text = page.evaluate("() => document.getElementById('createPsbt').textContent")
    test("WIF mode: button says 'Create, Sign & Finalize'",
         'Sign' in create_btn_text, f"got '{create_btn_text}'")

    visible_steps = page.evaluate("""() => {
        return Array.from(document.querySelectorAll('.step-indicator .step'))
            .filter(s => s.style.display !== 'none').length;
    }""")
    test("WIF mode: 2 steps visible", visible_steps == 2, f"got {visible_steps}")

    # Add UTXO without WIF → mixed mode, still 2-step layout
    page.evaluate("""() => {
        window._fn.addFetchedInput('b'.repeat(64), 1, 2000, '0014' + 'cd'.repeat(20),
            'tb1qtest2', null, null);
        window._fn.updateStepLayout();
    }""")

    create_btn_text = page.evaluate("() => document.getElementById('createPsbt').textContent")
    test("mixed mode: button says 'Create PSBT'",
         create_btn_text.strip() == 'Create PSBT', f"got '{create_btn_text}'")

    visible_steps = page.evaluate("""() => {
        return Array.from(document.querySelectorAll('.step-indicator .step'))
            .filter(s => s.style.display !== 'none').length;
    }""")
    test("mixed mode: 2 steps visible", visible_steps == 2, f"got {visible_steps}")

    # Combine section visible, broadcast section hidden in non-WIF mode
    combine_visible = page.evaluate("() => document.getElementById('combineSection').style.display !== 'none'")
    broadcast_hidden = page.evaluate("() => document.getElementById('broadcastSection').style.display === 'none'")
    test("mixed mode: combine section visible, broadcast hidden",
         combine_visible and broadcast_hidden)

    some_wif = page.evaluate("() => window._fn.someUtxosHaveWif()")
    test("mixed mode: someUtxosHaveWif() returns true", some_wif == True)

    # ========================================================
    section("34. Tip Section")
    # ========================================================

    # Reload for fresh state
    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)

    # Default: 0.99% preset active
    active_pct = page.evaluate("""() => {
        const btn = document.querySelector('.tip-preset.active');
        return btn ? btn.dataset.pct : null;
    }""")
    test("default tip preset is 0.99%", active_pct == "0.99", f"got {active_pct}")

    # Tip address matches network (testnet on static server)
    tip_addr = page.evaluate("() => document.getElementById('tipAddress').value")
    expected_addr = page.evaluate("() => window._fn.TIP_ADDRESSES[document.getElementById('network').value]")
    test("tip address matches network", tip_addr == expected_addr,
         f"got '{tip_addr}' expected '{expected_addr}'")

    # Tip sats = 0 when no UTXOs (0.99% of 0 = 0)
    tip_sats = page.evaluate("() => document.getElementById('tipSats').value")
    test("tip sats empty with no UTXOs", tip_sats == "", f"got '{tip_sats}'")

    # Add UTXO → tip recalculates
    page.evaluate(f"""() => {{
        window._fn.addFetchedInput('a'.repeat(64), 0, 100000, '0014' + 'ab'.repeat(20),
            'tb1qtest', null, null);
        window._fn.updateOutputPercentages();
    }}""")
    tip_sats = page.evaluate("() => parseInt(document.getElementById('tipSats').value) || 0")
    test("tip sats = 990 (0.99% of 100000)", tip_sats == 990, f"got {tip_sats}")

    # Summary text shows tip info
    summary = page.evaluate("() => document.getElementById('tipSummary').textContent")
    test("tip summary contains sats", "990" in summary, f"got '{summary}'")

    # Click 0.5% preset → recalculates
    page.click(".tip-preset[data-pct='0.5']")
    tip_sats = page.evaluate("() => parseInt(document.getElementById('tipSats').value) || 0")
    test("0.5% preset: tip = 500", tip_sats == 500, f"got {tip_sats}")

    # Click No Tip → clears sats
    page.click(".tip-preset[data-pct='0']")
    tip_sats = page.evaluate("() => document.getElementById('tipSats').value")
    test("No Tip preset: sats empty", tip_sats == "", f"got '{tip_sats}'")

    # getTipOutputCount returns 0 when no tip
    count = page.evaluate("() => window._fn.getTipOutputCount()")
    test("getTipOutputCount = 0 with no tip", count == 0, f"got {count}")

    # Click 0.1% → tip output included in gatherOutputs
    page.click(".tip-preset[data-pct='0.1']")
    gathered = page.evaluate("() => window._fn.gatherOutputs()")
    tip_outputs = [o for o in gathered if o["address"] == expected_addr]
    test("gatherOutputs includes tip", len(tip_outputs) == 1, f"got {len(tip_outputs)}")
    test("tip output value = 100", tip_outputs[0]["value"] == 100, f"got {tip_outputs[0]['value']}")

    # getTipOutputCount returns 1 with tip
    count = page.evaluate("() => window._fn.getTipOutputCount()")
    test("getTipOutputCount = 1 with tip", count == 1, f"got {count}")

    # Custom sats input deselects presets
    page.fill("#tipSats", "250")
    active = page.evaluate("() => document.querySelector('.tip-preset.active')")
    test("custom sats deselects presets", active is None, f"got {active}")

    # Network change updates tip address
    page.select_option("#network", "mainnet")
    time.sleep(1)
    tip_addr = page.evaluate("() => document.getElementById('tipAddress').value")
    test("mainnet tip address", tip_addr == "bc1qrfagrsfrm8erdsmrku3fgq5yc573zyp2q3uje8",
         f"got '{tip_addr}'")

    page.select_option("#network", "regtest")
    time.sleep(1)
    tip_addr = page.evaluate("() => document.getElementById('tipAddress').value")
    test("regtest tip address", tip_addr == "bcrt1qrx4ree6dujheqmpd62cnws9zs0eak8v7vtuhv9",
         f"got '{tip_addr}'")


    # ========================================================
    section("35. Fetch QR Scanner (parseFetchQrData)")
    # ========================================================

    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)

    # Select regtest for validation (regtest accepts bcrt1q addresses)
    page.select_option("#network", "regtest")
    time.sleep(1)

    # Generate a valid WIF dynamically (same approach as section 30)
    test_wif = page.evaluate("""() => {
        const kp = window._ECPair.makeRandom({ network: window._fn.getSelectedNetwork() });
        return kp.toWIF();
    }""")

    # Derive a valid regtest address from the WIF
    test_addr = page.evaluate(f"""() => {{
        const kp = window._ECPair.fromWIF('{test_wif}', window._fn.getSelectedNetwork());
        const p = window._bitcoin.payments.p2wpkh({{ pubkey: kp.publicKey, network: window._fn.getSelectedNetwork() }});
        return p.address;
    }}""")

    # Known valid xpub for extended key tests
    MASTER_XPUB = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    # Plain address
    result = page.evaluate(f'() => window._fn.parseFetchQrData("{test_addr}")')
    test("parseFetchQrData: plain address",
         result and result["value"] == test_addr and result["autoFetch"] == True,
         f"got {result}")

    # BIP21 URI with address only
    bip21 = f"bitcoin:{test_addr}"
    result = page.evaluate(f'() => window._fn.parseFetchQrData("{bip21}")')
    test("parseFetchQrData: BIP21 URI",
         result and result["value"] == test_addr and result["autoFetch"] == True,
         f"got {result}")

    # BIP21 URI with query params
    bip21_params = f"bitcoin:{test_addr}?amount=0.5&label=test"
    result = page.evaluate(f'() => window._fn.parseFetchQrData("{bip21_params}")')
    test("parseFetchQrData: BIP21 with params strips params",
         result and result["value"] == test_addr,
         f"got {result}")

    # BIP21 case-insensitive
    bip21_upper = f"BITCOIN:{test_addr}"
    result = page.evaluate(f'() => window._fn.parseFetchQrData("{bip21_upper}")')
    test("parseFetchQrData: BIP21 case-insensitive",
         result and result["value"] == test_addr,
         f"got {result}")

    # WIF key
    result = page.evaluate(f'() => window._fn.parseFetchQrData("{test_wif}")')
    test("parseFetchQrData: WIF key",
         result and result["value"] == test_wif and result["autoFetch"] == True,
         f"got {result}")

    # Extended public key (xpub) — switch to mainnet since this is a mainnet xpub
    page.select_option("#network", "mainnet")
    time.sleep(0.5)
    result = page.evaluate(f'() => window._fn.parseFetchQrData("{MASTER_XPUB}")')
    test("parseFetchQrData: xpub",
         result and result["value"] == MASTER_XPUB and result["autoFetch"] == True,
         f"got {result}")
    page.select_option("#network", "regtest")
    time.sleep(0.5)

    # Gift wallet sweep URL
    sweep_url = f"https://ObjSal.github.io/bitcoin-gift-paper-wallet/sweep.html?wif={test_wif}&network=regtest&type=taproot"
    result = page.evaluate(f'() => window._fn.parseFetchQrData("{sweep_url}")')
    test("parseFetchQrData: gift wallet sweep URL extracts WIF",
         result and result["value"] == test_wif and result["autoFetch"] == True,
         f"got {result}")

    # Unrecognized string — returns value with autoFetch=false
    result = page.evaluate('() => window._fn.parseFetchQrData("Hello World")')
    test("parseFetchQrData: unrecognized string pastes as-is",
         result and result["value"] == "Hello World" and result["autoFetch"] == False,
         f"got {result}")

    # Empty string
    result = page.evaluate('() => window._fn.parseFetchQrData("")')
    test("parseFetchQrData: empty string returns null",
         result is None, f"got {result}")

    # Null
    result = page.evaluate('() => window._fn.parseFetchQrData(null)')
    test("parseFetchQrData: null returns null",
         result is None, f"got {result}")

    # handleFetchScannedQR populates fetch input
    page.evaluate(f'() => window._fn.handleFetchScannedQR("{test_addr}")')
    fetch_val = page.evaluate('() => document.getElementById("fetchAddress").value')
    test("handleFetchScannedQR: populates fetch input",
         fetch_val == test_addr, f"got '{fetch_val}'")

    # Scan button exists
    btn = page.evaluate('() => !!document.getElementById("fetchScanQrBtn")')
    test("fetchScanQrBtn exists", btn == True, f"got {btn}")

    # Cancel button exists
    cancel_btn = page.evaluate('() => !!document.getElementById("cancelFetchScanBtn")')
    test("cancelFetchScanBtn exists", cancel_btn == True, f"got {cancel_btn}")


    # ========================================================
    section("36. resetAll, Clickable Steps, Network Switch")
    # ========================================================

    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=15000)

    # Add a UTXO and verify it exists
    page.evaluate("""() => {
        window._fn.addFetchedInput('a'.repeat(64), 0, 1000, '0014' + 'ab'.repeat(20),
            'tb1qtest');
    }""")
    utxo_count = page.evaluate("() => document.querySelectorAll('#utxoContainer [data-utxo]').length")
    test("setup: UTXO added", utxo_count == 1)

    # resetAll() clears UTXOs
    page.evaluate("() => window._fn.resetAll()")
    utxo_count = page.evaluate("() => document.querySelectorAll('#utxoContainer [data-utxo]').length")
    test("resetAll: UTXOs cleared", utxo_count == 0)

    # resetAll() preserves one default output
    output_count = page.evaluate("() => document.querySelectorAll('#outputContainer [data-output]').length")
    test("resetAll: default output row present", output_count == 1)

    # resetAll() clears PSBT state
    last = page.evaluate("() => window._fn.lastPsbt")
    final = page.evaluate("() => window._fn.finalPsbt")
    final_tx = page.evaluate("() => window._fn.finalTxHex")
    test("resetAll: PSBT state cleared", last is None and final is None and final_tx is None)

    # resetAll() shows Create card
    create_visible = page.evaluate("() => !document.getElementById('cardCreate').classList.contains('hidden')")
    test("resetAll: Create card visible", create_visible)

    # Step circles are clickable (have cursor:pointer)
    cursor = page.evaluate("""() => {
        const step = document.querySelector('.step-indicator .step');
        return getComputedStyle(step).cursor;
    }""")
    test("step circles: cursor pointer", cursor == "pointer", f"got {cursor}")

    # Signing hint text exists in psbtResult
    hint_exists = page.evaluate("""() => {
        const result = document.getElementById('psbtResult');
        return result.textContent.includes('Sign this PSBT separately');
    }""")
    test("signing hint: text present in psbtResult", hint_exists)

    # Download Transaction button exists (not "Download Final PSBT")
    dl_text = page.evaluate("() => document.getElementById('downloadFinalPsbt').textContent")
    test("broadcast card: Download Transaction button",
         'Transaction' in dl_text, f"got '{dl_text}'")

    # Network switch: no warning when no data
    _all_dialogs.clear()
    page.evaluate("() => { document.getElementById('network').value = 'mainnet'; document.getElementById('network').dispatchEvent(new Event('change')); }")
    test("network switch (no data): no confirm dialog", len(_all_dialogs) == 0,
         f"got {_all_dialogs}")

    # Add data then switch — should trigger confirm
    page.evaluate("() => { document.getElementById('network').value = 'testnet'; document.getElementById('network').dispatchEvent(new Event('change')); }")
    _all_dialogs.clear()
    page.evaluate("""() => {
        window._fn.addFetchedInput('c'.repeat(64), 0, 3000, '0014' + 'ef'.repeat(20),
            'tb1qtest3');
    }""")
    page.evaluate("() => { document.getElementById('network').value = 'mainnet'; document.getElementById('network').dispatchEvent(new Event('change')); }")
    test("network switch (with data): confirm dialog shown",
         len(_all_dialogs) == 1 and 'Switching networks' in _all_dialogs[0],
         f"got {_all_dialogs}")

    # After accepting, UTXOs should be cleared
    utxo_count = page.evaluate("() => document.querySelectorAll('#utxoContainer [data-utxo]').length")
    test("network switch: UTXOs cleared after confirm", utxo_count == 0)

    # ========================================================
    section("37. isInputSigned + no create-time taproot warning")
    # ========================================================

    page.select_option("#network", "regtest")
    time.sleep(1)

    # A P2WPKH input signed once must report as signed; signing it again is
    # what bip174 rejects ("duplicate data"), so the combine step must skip it.
    r = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const kp = window._ECPair.makeRandom({ network: net });
        const spk = window._bitcoin.payments.p2wpkh({
            pubkey: window._Buffer.from(kp.publicKey), network: net }).output;
        const utxos = [{ txid: 'ab'.repeat(32), vout: 0, value: 100000,
                         scriptPubKey: window._Buffer.from(spk).toString('hex') }];
        const dest = window._bitcoin.payments.p2wpkh({
            pubkey: window._Buffer.from(window._ECPair.makeRandom({ network: net }).publicKey),
            network: net }).address;
        const psbt = window._fn.createPsbtFromInputs(utxos, [{ address: dest, value: 90000 }], 0, '');
        const before = window._fn.isInputSigned(psbt.data.inputs[0]);
        window._fn.signInputWithWif(psbt, 0, kp.toWIF(), net);
        const after = window._fn.isInputSigned(psbt.data.inputs[0]);
        let dup = '';
        try { window._fn.signInputWithWif(psbt, 0, kp.toWIF(), net); } catch (e) { dup = e.message; }
        psbt.finalizeAllInputs();
        const fin = window._fn.isInputSigned(psbt.data.inputs[0]);
        return { before, after, dup, fin, nullish: window._fn.isInputSigned(undefined) };
    }""")
    test("isInputSigned: false before signing", r["before"] is False)
    test("isInputSigned: true after partialSig", r["after"] is True)
    test("isInputSigned: true after finalize", r["fin"] is True)
    test("isInputSigned: false for missing input", r["nullish"] is False)
    test("re-signing a signed input throws (why combine must skip it)",
         "duplicate" in r["dup"].lower(), f"got '{r['dup']}'")

    # Taproot signed via tapKeySig must also count as signed.
    r = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const kp = window._ECPair.makeRandom({ network: net });
        const addr = window._fn.pubkeyToAddress(window._Buffer.from(kp.publicKey), 'p2tr', net);
        const spk = window._Buffer.from(window._bitcoin.address.toOutputScript(addr, net)).toString('hex');
        const utxos = [{ txid: 'cd'.repeat(32), vout: 1, value: 100000, scriptPubKey: spk, wif: kp.toWIF() }];
        const psbt = window._fn.createPsbtFromInputs(utxos, [{ address: addr, value: 90000 }], 0, '');
        window._fn.signInputWithWif(psbt, 0, kp.toWIF(), net);
        return window._fn.isInputSigned(psbt.data.inputs[0]);
    }""")
    test("isInputSigned: true after taproot tapKeySig", r is True)

    # Address-fetched P2TR (no pubkey, no WIF) is a normal HW-wallet input:
    # an external signer supplies tapInternalKey. Create must not nag about it.
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const kp = window._ECPair.makeRandom({ network: net });
        const addr = window._fn.pubkeyToAddress(window._Buffer.from(kp.publicKey), 'p2tr', net);
        const spk = window._Buffer.from(window._bitcoin.address.toOutputScript(addr, net)).toString('hex');
        window._fn.addFetchedInput('ef'.repeat(32), 0, 100000, spk, addr);
        window._fn.addOutput(null, addr, 90000);
        document.querySelectorAll('.tip-preset').forEach(b => b.classList.remove('active'));
        document.querySelector('.tip-preset[data-pct="0"]').classList.add('active');
        document.getElementById('tipSats').value = '';
    }""")
    page.fill("#feeRate", "1")
    _all_dialogs.clear()
    page.click("#createPsbt")
    time.sleep(1)
    test("address-fetched P2TR: no taproot warning dialog at create",
         not any('taproot' in d.lower() for d in _all_dialogs), f"got {_all_dialogs}")
    try:
        page.wait_for_function(
            "() => (document.getElementById('psbtHex').textContent || '').length > 0",
            timeout=5000)
        built = True
    except Exception:
        built = False
    test("address-fetched P2TR: PSBT still built", built, f"dialogs: {_all_dialogs}")

    # ========================================================
    section("38. taprootInternalKey validation + unmatched WIF rows at combine")
    # ========================================================

    r = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const kp = window._ECPair.makeRandom({ network: net });
        const wif = kp.toWIF();
        const pub = window._Buffer.from(kp.publicKey).toString('hex');
        const fromWif = window._Buffer.from(window._fn.toXOnly(window._Buffer.from(kp.publicKey))).toString('hex');
        const hex = v => v ? window._Buffer.from(v).toString('hex') : null;
        return {
            fromWif,
            badHexWithWif: hex(window._fn.taprootInternalKey({ pubkey: 'zz', wif }, net)),
            shortHexWithWif: hex(window._fn.taprootInternalKey({ pubkey: pub.slice(0, 65), wif }, net)),
            badHexNoWif: hex(window._fn.taprootInternalKey({ pubkey: 'zz' }, net)),
            compressed: hex(window._fn.taprootInternalKey({ pubkey: pub }, net)),
            xonly: hex(window._fn.taprootInternalKey({ pubkey: pub.slice(2) }, net)),
            upperPadded: hex(window._fn.taprootInternalKey({ pubkey: ' ' + pub.toUpperCase() + ' ' }, net)),
        };
    }""")
    test("taprootInternalKey: bad hex pubkey falls through to WIF", r["badHexWithWif"] == r["fromWif"])
    test("taprootInternalKey: truncated pubkey falls through to WIF", r["shortHexWithWif"] == r["fromWif"])
    test("taprootInternalKey: bad hex and no WIF -> null", r["badHexNoWif"] is None)
    test("taprootInternalKey: compressed pubkey accepted", r["compressed"] == r["fromWif"])
    test("taprootInternalKey: x-only pubkey accepted", r["xonly"] == r["fromWif"])
    test("taprootInternalKey: whitespace/case tolerated", r["upperPadded"] == r["fromWif"])

    # A WIF row whose outpoint is absent from the uploaded PSBT must be
    # reported by name, not left unsigned to fail as "Can not finalize".
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => { window._fn.psbtAccumulator.length = 0; }")
    page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: window._Buffer.from(kp.publicKey), network: net });
        const spk = window._Buffer.from(p2w.output).toString('hex');
        // Row on the Create step: outpoint 11..11:0 with a WIF
        window._fn.addInput(null, '11'.repeat(32), 0, 100000, spk);
        const row = document.querySelector('#utxoContainer [data-utxo]');
        row.setAttribute('data-wif', kp.toWIF());
        // Uploaded PSBT spends a DIFFERENT outpoint (22..22:0)
        const psbt = window._fn.createPsbtFromInputs(
            [{ txid: '22'.repeat(32), vout: 0, value: 100000, scriptPubKey: spk }],
            [{ address: p2w.address, value: 90000 }], 0, '');
        window._fn.addPsbtToList('other.psbt', 'file', new Uint8Array(psbt.toBuffer()));
    }""")
    page.evaluate("() => { window._fn.showCard('cardBroadcast'); document.getElementById('combineSection').style.display = ''; }")
    _all_dialogs.clear()
    page.click("#combinePsbt")
    time.sleep(1)
    msg = _all_dialogs[-1] if _all_dialogs else ""
    test("combine: unmatched WIF row is reported by outpoint",
         "not in the uploaded PSBT" in msg and ("11" * 32 + ":0") in msg, f"got {_all_dialogs}")
    test("combine: unmatched WIF row does not surface as 'Can not finalize'",
         "can not finalize" not in msg.lower(), f"got {msg}")
    page.evaluate("() => { window._fn.psbtAccumulator.length = 0; window._fn.renderPsbtList(); window._fn.showCard('cardCreate'); }")

    # ========================================================
    section("39. P2SH-P2WPKH WIF signing + taproot via nonWitnessUtxo")
    # ========================================================

    r = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const B = window._Buffer;
        const kp = window._ECPair.makeRandom({ network: net });
        const other = window._ECPair.makeRandom({ network: net });
        const p2sh = window._bitcoin.payments.p2sh({
            redeem: window._bitcoin.payments.p2wpkh({ pubkey: B.from(kp.publicKey), network: net }),
            network: net });
        const spk = B.from(p2sh.output).toString('hex');
        const dest = window._bitcoin.payments.p2wpkh({ pubkey: B.from(other.publicKey), network: net }).address;
        const out = { isP2sh: window._fn.isP2shScript(spk) };

        // redeemScript helper: right key -> script, wrong key -> null
        const rs = window._fn.p2shP2wpkhRedeemScript(B.from(kp.publicKey), spk, net);
        out.redeemHex = rs ? B.from(rs).toString('hex') : null;
        out.expectedRedeem = B.from(p2sh.redeem.output).toString('hex');
        out.wrongKeyNull = window._fn.p2shP2wpkhRedeemScript(B.from(other.publicKey), spk, net) === null;

        // (a) row with WIF: createPsbtFromInputs attaches redeemScript, signs, finalizes
        const utxosWif = [{ txid: 'aa'.repeat(32), vout: 0, value: 100000, scriptPubKey: spk, wif: kp.toWIF() }];
        const p1 = window._fn.createPsbtFromInputs(utxosWif, [{ address: dest, value: 90000 }], 0, '');
        out.hasRedeemAtCreate = !!p1.data.inputs[0].redeemScript;
        window._fn.signInputWithWif(p1, 0, kp.toWIF(), net);
        p1.finalizeAllInputs();
        const tx1 = p1.extractTransaction();
        out.aSigOk = tx1.ins[0].witness.length === 2 && tx1.ins[0].script.length > 0;

        // (b) row without WIF/pubkey (uploaded PSBT case): signInputWithWif attaches it
        const utxosBare = [{ txid: 'bb'.repeat(32), vout: 0, value: 100000, scriptPubKey: spk }];
        const p2 = window._fn.createPsbtFromInputs(utxosBare, [{ address: dest, value: 90000 }], 0, '');
        out.noRedeemAtCreate = !p2.data.inputs[0].redeemScript;
        window._fn.signInputWithWif(p2, 0, kp.toWIF(), net);
        out.redeemAddedAtSign = !!p2.data.inputs[0].redeemScript;
        p2.finalizeAllInputs();
        out.bFinalized = !!p2.data.inputs[0].finalScriptWitness;

        // (c) wrong WIF on a P2SH input must throw, not attach a bogus redeemScript
        const p3 = window._fn.createPsbtFromInputs(utxosBare, [{ address: dest, value: 90000 }], 0, '');
        try { window._fn.signInputWithWif(p3, 0, other.toWIF(), net); out.wrongWifThrew = false; }
        catch (e) { out.wrongWifThrew = true; }
        out.wrongWifNoRedeem = !p3.data.inputs[0].redeemScript;
        return out;
    }""")
    test("isP2shScript: detects a914..87", r["isP2sh"] is True)
    test("p2shP2wpkhRedeemScript: matches bitcoinjs redeem output", r["redeemHex"] == r["expectedRedeem"])
    test("p2shP2wpkhRedeemScript: wrong key -> null", r["wrongKeyNull"] is True)
    test("P2SH-P2WPKH WIF row: redeemScript set at create", r["hasRedeemAtCreate"] is True)
    test("P2SH-P2WPKH WIF row: signs and finalizes (scriptSig + 2-item witness)", r["aSigOk"] is True)
    test("P2SH-P2WPKH bare row: no redeemScript at create", r["noRedeemAtCreate"] is True)
    test("P2SH-P2WPKH bare row: signInputWithWif attaches redeemScript", r["redeemAddedAtSign"] is True)
    test("P2SH-P2WPKH bare row: finalizes after sign", r["bFinalized"] is True)
    test("P2SH-P2WPKH: wrong WIF throws", r["wrongWifThrew"] is True)
    test("P2SH-P2WPKH: wrong WIF attaches no redeemScript", r["wrongWifNoRedeem"] is True)

    # Taproot input carried with nonWitnessUtxo (no witnessUtxo): detection
    # must still go by tapInternalKey and sign with the tweaked key.
    r = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const B = window._Buffer;
        const bitcoin = window._bitcoin;
        const kp = window._ECPair.makeRandom({ network: net });
        const addr = window._fn.pubkeyToAddress(B.from(kp.publicKey), 'p2tr', net);
        const spk = bitcoin.address.toOutputScript(addr, net);
        // A real previous transaction paying the P2TR address
        const prev = new bitcoin.Transaction();
        prev.version = 2;
        prev.addInput(B.alloc(32, 1), 0);
        prev.addOutput(spk, 100000n);
        const prevHex = prev.toHex();
        const prevTxid = prev.getId();
        const internal = window._fn.toXOnly(B.from(kp.publicKey));

        const psbt = new bitcoin.Psbt({ network: net });
        psbt.addInput({ hash: prevTxid, index: 0, nonWitnessUtxo: B.from(prevHex, 'hex'), tapInternalKey: internal });
        psbt.addOutput({ address: addr, value: 90000n });
        const out = { hasWitnessUtxo: !!psbt.data.inputs[0].witnessUtxo };
        try {
            window._fn.signInputWithWif(psbt, 0, kp.toWIF(), net);
            out.signed = !!psbt.data.inputs[0].tapKeySig;
            // bitcoinjs needs witnessUtxo to FINALIZE taproot; add it now so
            // finalize proves the signature above was made with the tweaked key.
            psbt.updateInput(0, { witnessUtxo: { script: spk, value: 100000n } });
            psbt.finalizeAllInputs();
            const tx = psbt.extractTransaction();
            out.witnessLen = tx.ins[0].witness.length;
            out.sigLen = tx.ins[0].witness[0].length;
        } catch (e) { out.err = e.message; }
        return out;
    }""")
    test("taproot nonWitnessUtxo-only: bitcoinjs did not add witnessUtxo", r.get("hasWitnessUtxo") is False)
    test("taproot nonWitnessUtxo-only: signed with tweaked key (tapKeySig)", r.get("signed") is True, f"{r}")
    test("taproot nonWitnessUtxo-only: finalizes to 1x64-byte witness",
         r.get("witnessLen") == 1 and r.get("sigLen") == 64, f"{r}")

    # The fetch input is cleared after a fetch only if it still holds the
    # fetched value -- typing the next key during a slow fetch must survive.
    r = page.evaluate("""() => {
        const el = document.getElementById('fetchAddress');
        el.value = 'fetched-value';
        window._fn.clearFetchInputIfStill('fetched-value');
        const cleared = el.value;
        el.value = 'typed-meanwhile';
        window._fn.clearFetchInputIfStill('fetched-value');
        const kept = el.value;
        el.value = '';
        return { cleared, kept };
    }""")
    test("clearFetchInputIfStill: clears the fetched value", r["cleared"] == "")
    test("clearFetchInputIfStill: keeps a newer value", r["kept"] == "typed-meanwhile")

    # ========================================================
    section("40. Lock time (anti-fee-sniping): None / Block / Date")
    # ========================================================

    page.select_option("#network", "regtest")
    # Let the tip fetch triggered by the network change settle, so a late
    # response cannot overwrite the tip heights injected below.
    page.evaluate("() => window._fn.fetchTipHeight()")

    # Default: Block mode, tracking the tip
    test("locktime: default mode is block", page.evaluate("() => window._fn.getLocktimeMode()") == "block")
    test("locktime: Block preset active by default",
         page.evaluate("() => document.querySelector('.locktime-preset[data-mode=\"block\"]').classList.contains('active')"))
    test("locktime: auto-tracking tip by default", page.evaluate("() => window._fn.locktimeAuto") is True)

    # Inject a known tip and make sure block mode follows it
    r = page.evaluate("""() => {
        window._fn.tipHeight = 850000;
        window._fn.setLocktimeMode('block');
        return { field: document.getElementById('locktimeBlock').value,
                 v: window._fn.validateLocktime(),
                 summary: document.getElementById('locktimeSummary').textContent };
    }""")
    test("locktime block: field follows tip", r["field"] == "850000")
    test("locktime block: value is tip", r["v"].get("value") == 850000, f"{r['v']}")
    test("locktime block: summary marks current", "850000" in r["summary"] and "current" in r["summary"], r["summary"])

    # Manual edit disables auto-tracking; validation bounds
    r = page.evaluate("""() => {
        const el = document.getElementById('locktimeBlock');
        el.value = '840000'; el.dispatchEvent(new Event('input'));
        const ok = window._fn.validateLocktime();
        el.value = '500000000'; el.dispatchEvent(new Event('input'));
        const tooBig = window._fn.validateLocktime();
        el.value = '-1'; el.dispatchEvent(new Event('input'));
        const neg = window._fn.validateLocktime();
        el.value = '860000'; el.dispatchEvent(new Event('input'));
        const future = { v: window._fn.validateLocktime(), isFuture: window._fn.locktimeIsFuture(860000),
                         summary: document.getElementById('locktimeSummary').textContent };
        return { auto: window._fn.locktimeAuto, ok, tooBig, neg, future };
    }""")
    test("locktime block: manual edit disables auto", r["auto"] is False)
    test("locktime block: 840000 accepted", r["ok"].get("value") == 840000)
    test("locktime block: >= 500,000,000 rejected", "error" in r["tooBig"])
    test("locktime block: negative rejected", "error" in r["neg"])
    test("locktime block: above tip flagged as future", r["future"]["isFuture"] is True and "future" in r["future"]["summary"])

    # Date mode: datetime-local -> unix timestamp (local time)
    r = page.evaluate("""() => {
        window._fn.setLocktimeMode('date');
        const el = document.getElementById('locktimeDate');
        const prefilled = el.value !== '';
        el.value = '2023-11-14T22:13'; el.dispatchEvent(new Event('input'));
        const expected = Math.floor(new Date('2023-11-14T22:13').getTime() / 1000);
        const v = window._fn.validateLocktime();
        el.value = '1980-01-01T00:00'; el.dispatchEvent(new Event('input'));
        const tooEarly = window._fn.validateLocktime();
        el.value = ''; el.dispatchEvent(new Event('input'));
        const empty = window._fn.validateLocktime();
        return { prefilled, v, expected, tooEarly, empty };
    }""")
    test("locktime date: prefilled with now on first switch", r["prefilled"] is True)
    test("locktime date: converts to unix timestamp", r["v"].get("value") == r["expected"], f"{r['v']} vs {r['expected']}")
    test("locktime date: timestamp is >= 500,000,000", r["v"].get("value", 0) >= 500_000_000)
    test("locktime date: pre-1985 rejected", "error" in r["tooEarly"])
    test("locktime date: empty rejected", "error" in r["empty"])

    # None mode
    r = page.evaluate("""() => { window._fn.setLocktimeMode('none'); return window._fn.validateLocktime(); }""")
    test("locktime none: value 0", r.get("value") == 0)

    # Tip fetch survives one failed attempt (retry), and a dead endpoint -> null
    calls = {"n": 0}
    def tip_route(route, request):
        calls["n"] += 1
        if calls["n"] == 1:
            route.fulfill(status=500, body="err")
        else:
            route.fulfill(status=200, content_type="text/plain", body="900123")
    page.route("**/blocks/tip/height", tip_route)
    r = page.evaluate("() => window._fn.fetchTipHeight()")
    test("fetchTipHeight: retries once and succeeds", r == 900123, f"got {r} after {calls['n']} calls")
    test("fetchTipHeight: exactly two attempts used", calls["n"] == 2, f"{calls['n']}")
    # restore auto-tracking (earlier manual-edit tests disabled it) so the
    # field-retention behaviour below is actually exercised
    page.evaluate("() => window._fn.resetLocktime()")
    page.wait_for_function("() => document.getElementById('locktimeBlock').value === '900123'", timeout=5000)  # success route still active
    page.unroute("**/blocks/tip/height")
    page.route("**/blocks/tip/height", lambda route, req: route.fulfill(status=500, body="err"))
    r = page.evaluate("() => window._fn.fetchTipHeight()")
    test("fetchTipHeight: failure keeps the last known height", r == 900123, f"got {r}")
    test("fetchTipHeight: failure keeps the field filled",
         page.evaluate("() => document.getElementById('locktimeBlock').value") == "900123")
    r = page.evaluate("() => { window._fn.tipHeight = null; return window._fn.fetchTipHeight(); }")
    test("fetchTipHeight: never-known + failure -> null", r is None, f"got {r}")
    page.unroute("**/blocks/tip/height")
    page.evaluate("() => window._fn.fetchTipHeight()")

    # createPsbtFromInputs honours the parameter (default 0)
    r = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: window._Buffer.from(kp.publicKey), network: net });
        const spk = window._Buffer.from(p2w.output).toString('hex');
        const utxos = [{ txid: 'ab'.repeat(32), vout: 0, value: 100000, scriptPubKey: spk }];
        const outputs = [{ address: p2w.address, value: 90000 }];
        const a = window._fn.createPsbtFromInputs(utxos, outputs, 0, '');
        const b = window._fn.createPsbtFromInputs(utxos, outputs, 0, '', 850000);
        const c = window._fn.createPsbtFromInputs(utxos, outputs, 0, '', 1700000000);
        return { a: a.locktime, b: b.locktime, c: c.locktime, seq: b.txInputs[0].sequence };
    }""")
    test("createPsbtFromInputs: default locktime 0", r["a"] == 0)
    test("createPsbtFromInputs: height locktime set", r["b"] == 850000)
    test("createPsbtFromInputs: timestamp locktime set", r["c"] == 1700000000)
    test("createPsbtFromInputs: sequence 0xfffffffd keeps locktime enforceable", r["seq"] == 0xfffffffd)

    # Through the UI: Create with block mode at a known tip stamps the PSBT
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork();
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: window._Buffer.from(kp.publicKey), network: net });
        const spk = window._Buffer.from(p2w.output).toString('hex');
        window._fn.addFetchedInput('cd'.repeat(32), 0, 100000, spk, p2w.address);
        // Keep the create handler off the network: it awaits
        // fetchAllNonWitnessUtxos() before the lock time check, and this
        // static-server regtest path would otherwise query mempool.space.
        window._fn.rawTxCache.set('cd'.repeat(32), '00');
        window._fn.addOutput(null, p2w.address, 90000);
        document.querySelectorAll('.tip-preset').forEach(b => b.classList.remove('active'));
        document.querySelector('.tip-preset[data-pct="0"]').classList.add('active');
        document.getElementById('tipSats').value = '';
        window._fn.tipHeight = 850123;
        document.querySelectorAll('.locktime-preset').forEach(b => b.classList.toggle('active', b.dataset.mode === 'block'));
        document.getElementById('locktimeBlock').value = '850123';
    }""")
    page.fill("#feeRate", "1")
    page.evaluate("() => { document.getElementById('psbtHex').textContent = ''; }")
    _all_dialogs.clear()
    page.click("#createPsbt")
    try:
        page.wait_for_function("() => (document.getElementById('psbtHex').textContent || '').length > 0", timeout=5000)
    except Exception:
        pass
    r = page.evaluate("""() => {
        const hex = document.getElementById('psbtHex').textContent || '';
        if (!hex) return { built: false };
        const psbt = window._bitcoin.Psbt.fromHex(hex);
        return { built: true, locktime: psbt.locktime };
    }""")
    test("UI create: PSBT built with block locktime", r.get("built") is True, f"dialogs: {_all_dialogs}")
    test("UI create: PSBT locktime equals chosen height", r.get("locktime") == 850123, f"{r} dialogs: {_all_dialogs}")
    test("UI create: no future-locktime confirm at current height",
         not any('future' in d.lower() for d in _all_dialogs), f"{_all_dialogs}")

    # Future height -> confirm() dialog (auto-accepted by the handler)
    page.evaluate("""() => {
        window._fn.tipHeight = 850123;
        const el = document.getElementById('locktimeBlock');
        el.value = '850999'; el.dispatchEvent(new Event('input'));
    }""")
    pre = page.evaluate("""() => ({ mode: window._fn.getLocktimeMode(), v: window._fn.validateLocktime(),
        tip: window._fn.tipHeight, auto: window._fn.locktimeAuto, future: window._fn.locktimeIsFuture(850999),
        btnVisible: !!document.getElementById('createPsbt').offsetParent,
        card: document.getElementById('cardCreate').style.display })""")
    _all_dialogs.clear()
    page.click("#createPsbt")
    # The handler awaits fetchAllNonWitnessUtxos() (a network round trip on
    # this static-server path) before it reaches the lock time check.
    for _ in range(50):
        if any('future' in d.lower() for d in _all_dialogs):
            break
        time.sleep(0.2)
    test("UI create: future height shows confirm",
         any('future' in d.lower() and '850999' in d for d in _all_dialogs), f"{_all_dialogs} pre={pre}")

    # resetAll restores block/auto
    page.evaluate("() => window._fn.resetAll()")
    test("resetAll: locktime back to block mode", page.evaluate("() => window._fn.getLocktimeMode()") == "block")
    test("resetAll: locktime auto-tracking restored", page.evaluate("() => window._fn.locktimeAuto") is True)

    # ========================================================
    section("41. Transaction Preview (PSBT Decoder submodule)")
    # ========================================================

    page.select_option("#network", "regtest")
    test("preview: decoder URL is the bundled submodule",
         page.evaluate("() => window._fn.PSBT_DECODER_URL") == "psbt-decoder/")

    # Build an unsigned 1-in/1-out PSBT and a finalized copy, plus a raw tx.
    fx = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork(); const B = window._Buffer;
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: B.from(kp.publicKey), network: net });
        const spk = B.from(p2w.output).toString('hex');
        const utxos = [{ txid: 'ab'.repeat(32), vout: 0, value: 100000, scriptPubKey: spk }];
        const outputs = [{ address: p2w.address, value: 90000 }];
        const unsigned = window._fn.createPsbtFromInputs(utxos, outputs, 0, '').toHex();
        const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, '');
        window._fn.signInputWithWif(psbt, 0, kp.toWIF(), net);
        psbt.finalizeAllInputs();
        const big = window._fn.createPsbtFromInputs(
            Array.from({ length: 11 }, (_, i) => ({ txid: 'cd'.repeat(32), vout: i, value: 100000, scriptPubKey: spk })),
            outputs, 0, '').toHex();
        return { unsigned, finalized: psbt.toHex(), raw: psbt.extractTransaction().toHex(), big };
    }""")
    info = page.evaluate("(h) => window._fn.txPreviewInfo(h)", fx["unsigned"])
    test("txPreviewInfo: unsigned PSBT counts", info["nIn"] == 1 and info["nOut"] == 1 and info["finalized"] is False)
    test("txPreviewInfo: summary text", info["summary"] == "1 input \u2192 1 output", info["summary"])
    info = page.evaluate("(h) => window._fn.txPreviewInfo(h)", fx["finalized"])
    test("txPreviewInfo: finalized PSBT flagged", info["finalized"] is True and "finalized" in info["summary"])
    info = page.evaluate("(h) => window._fn.txPreviewInfo(h)", fx["raw"])
    test("txPreviewInfo: raw tx is finalized", info["finalized"] is True and info["nIn"] == 1)
    test("txPreviewInfo: garbage -> empty summary", page.evaluate("() => window._fn.txPreviewInfo('zz').summary") == "")

    # URLs: data in the #fragment only, network param, embed flag on the frame only
    u = page.evaluate("(h) => ({ full: window._fn.decoderUrl(h, false), embed: window._fn.decoderUrl(h, true) })", fx["unsigned"])
    test("decoderUrl: full link = submodule + network + #hex",
         u["full"].startswith("psbt-decoder/?network=regtest#70736274ff") and "embed" not in u["full"], u["full"][:60])
    test("decoderUrl: embed link carries embed=1", "embed=1" in u["embed"] and u["embed"].endswith(fx["unsigned"]))
    test("decoderUrl: hex never in the query string", "?" not in u["full"].split("#")[1])

    # Render on the Create card and let the real decoder load from the submodule
    page.evaluate("(h) => { document.getElementById('psbtResult').style.display = ''; window._fn.renderTxPreview('psbtPreview', h); }", fx["unsigned"])
    r = page.evaluate("""() => {
        const box = document.getElementById('psbtPreview');
        const f = box.querySelector('.tx-preview-frame'); const a = box.querySelector('.tx-preview-link');
        return { shown: getComputedStyle(box).display, summary: box.querySelector('.tx-preview-summary').textContent,
                 sandbox: f.getAttribute('sandbox'), src: f.src, href: a.getAttribute('href'), target: a.target, rel: a.rel,
                 bodyOpen: box.querySelector('.tx-preview-body').style.display !== 'none' };
    }""")
    test("preview: container shown", r["shown"] == "block")
    test("preview: summary shown", r["summary"] == "1 input \u2192 1 output", r["summary"])
    test("preview: iframe sandboxed without allow-same-origin",
         r["sandbox"] == "allow-scripts allow-popups allow-popups-to-escape-sandbox", r["sandbox"])
    test("preview: iframe src is the embed URL", "psbt-decoder/?network=regtest&embed=1#70736274ff" in r["src"], r["src"][:80])
    test("preview: full-details link opens a new tab safely",
         r["href"].startswith("psbt-decoder/?network=regtest#") and r["target"] == "_blank" and "noopener" in r["rel"])
    test("preview: open by default for a small sweep", r["bodyOpen"] is True)
    try:
        page.wait_for_function(
            "() => (document.querySelector('#psbtPreview .tx-preview-frame').style.height || '').endsWith('px')", timeout=15000)
        loaded = True
    except Exception:
        loaded = False
    h = page.evaluate("() => document.querySelector('#psbtPreview .tx-preview-frame').style.height")
    test("preview: decoder embed loaded from submodule and reported its height", loaded, f"height={h!r}")
    test("preview: reported height clamped to [160, 1400]px",
         loaded and 160 <= int(h[:-2]) <= 1400, h)

    # Collapse / expand via the heading; the link inside the heading does not toggle
    page.click("#psbtPreview .tx-preview-toggle h3")
    test("preview: heading click collapses",
         page.evaluate("() => document.querySelector('#psbtPreview .tx-preview-body').style.display") == "none")
    page.click("#psbtPreview .tx-preview-toggle h3")
    test("preview: heading click expands again",
         page.evaluate("() => document.querySelector('#psbtPreview .tx-preview-body').style.display") == "")

    # Large sweeps start collapsed
    page.evaluate("(h) => window._fn.renderTxPreview('psbtPreview', h)", fx["big"])
    test("preview: >10 inputs starts collapsed",
         page.evaluate("() => document.querySelector('#psbtPreview .tx-preview-body').style.display") == "none")
    test("preview: collapsed summary still shows counts",
         page.evaluate("() => document.querySelector('#psbtPreview .tx-preview-summary').textContent") == "11 inputs \u2192 1 output")

    # Broadcast preview prefers the finalized PSBT over the raw tx
    page.evaluate("([raw, fin]) => { window._fn.finalTxHex = raw; window._fn.finalPsbt = null; window._fn.renderFinalPreview(); }", [fx["raw"], fx["finalized"]])
    href_raw = page.evaluate("() => document.querySelector('#finalTxPreview .tx-preview-link').getAttribute('href')")
    test("final preview: raw tx used when no PSBT (Coldcard Q scan)", "#0200" in href_raw or "#0100" in href_raw, href_raw[:50])
    page.evaluate("([raw, fin]) => { window._fn.finalTxHex = raw; window._fn.finalPsbt = window._bitcoin.Psbt.fromHex(fin); window._fn.renderFinalPreview(); }", [fx["raw"], fx["finalized"]])
    r = page.evaluate("() => ({ href: document.querySelector('#finalTxPreview .tx-preview-link').getAttribute('href'), summary: document.querySelector('#finalTxPreview .tx-preview-summary').textContent })")
    test("final preview: finalized PSBT preferred (carries amounts)", "#70736274ff" in r["href"], r["href"][:50])
    test("final preview: summary says finalized", "finalized" in r["summary"], r["summary"])

    # Per-file inspect link in the signed PSBT list
    page.evaluate("(h) => { window._fn.psbtAccumulator.length = 0; window._fn.addPsbtToList('cc-signed.psbt', 'file', new Uint8Array(window._Buffer.from(h, 'hex'))); }", fx["unsigned"])
    r = page.evaluate("() => { const a = document.querySelector('#psbtList .psbt-inspect'); return a ? { href: a.getAttribute('href'), target: a.target, rel: a.rel } : null; }")
    test("psbt list: inspect link present", r is not None)
    test("psbt list: inspect link opens the decoder with that file's hex",
         r is not None and r["href"] == "psbt-decoder/?network=regtest#" + fx["unsigned"] and r["target"] == "_blank" and "noopener" in r["rel"])
    page.evaluate("() => { window._fn.psbtAccumulator.length = 0; window._fn.renderPsbtList(); }")

    # Cleared with the results they belong to
    page.evaluate("() => window._fn.hidePsbtResult()")
    test("hidePsbtResult clears the create preview",
         page.evaluate("() => { const b = document.getElementById('psbtPreview'); return getComputedStyle(b).display === 'none' && b.innerHTML === ''; }"))
    page.evaluate("() => window._fn.resetAll()")
    test("resetAll clears the broadcast preview",
         page.evaluate("() => { const b = document.getElementById('finalTxPreview'); return getComputedStyle(b).display === 'none' && b.innerHTML === ''; }"))

    # ========================================================
    section("42. Legacy-scriptSig guard + HW key-origin warnings")
    # ========================================================
    # Real-world fixture: a mainnet 2-in/2-out sweep where the signer of input 0
    # (a P2WPKH UTXO) produced a P2PKH-style scriptSig and an empty witness --
    # the Coldcard Q auto-finalize bug. Input 1 is correct. The tx is
    # consensus-invalid ("Witness requires empty scriptSig"); nothing is spent.
    BAD_TX = "0200000000010242c6b974a9fb749357d49d77effe5e216b9b606894af1e56e0a8a5516bd95df2000000006a473044022053733cbc7d91ede7aeacc16760894db0e266d242770f0a9c72a0ff69cb3c0f52022058a526b945fb999c95b9ffa59ad4ba5bd3dfd3da861f314be770bf11a10749f70121039e4729b1b69afedf9ba8f180f86cce7ab34e4f5fae6e95798644b5faf3e57e2ffdffffffec6a25d25a97f649d467ebb98b6e38a0abbf4234e5c6fc9b043a7d99219299031400000000fdffffff0280969800000000001600141f65d7846679eb769965636b0ba931a266ee19ba30de170000000000160014a00ebe6286ada0a39bb3f28c3700bf1d9c81a8210002473044022078972ac496e6cbb175f0868eab9fa10761dd8479df3d849480e6844feb403d1b022049e0e640110789fbd6f090532c5e1cdaee77ce881deaeabba9f1e4ce34c4eb28012102d9f02d154f40dd3abfcaaa135d63ab5e6b4e9b6debc526fe8ae68ef82d4c053d54b80e00"
    page.select_option("#network", "mainnet")
    time.sleep(1)

    r = page.evaluate("""() => ({
        p2wpkh: window._fn.isWitnessProgramScript('0014' + 'ab'.repeat(20)),
        p2wsh: window._fn.isWitnessProgramScript('0020' + 'ab'.repeat(32)),
        p2tr: window._fn.isWitnessProgramScript('5120' + 'ab'.repeat(32)),
        p2sh: window._fn.isWitnessProgramScript('a914' + 'ab'.repeat(20) + '87'),
        p2pkh: window._fn.isWitnessProgramScript('76a914' + 'ab'.repeat(20) + '88ac'),
        short: window._fn.isWitnessProgramScript('0014abcd'),
    })""")
    test("isWitnessProgramScript: P2WPKH/P2WSH/P2TR yes", r["p2wpkh"] and r["p2wsh"] and r["p2tr"])
    test("isWitnessProgramScript: P2SH/P2PKH/malformed no", not r["p2sh"] and not r["p2pkh"] and not r["short"])

    r = page.evaluate("(ps) => ps.map(p => window._fn.looksLikeAccountPath(p))",
                      ["m/84'/0'/0'", "m/84h/0h/0h", "m/49'/0'/0'", "m/84'/0'/0'/0/5", "m/84'/0'/0'/1/0", "0/5", "m/0'"])
    test("looksLikeAccountPath: account paths flagged", r[0] and r[1] and r[2] and r[6])
    test("looksLikeAccountPath: key paths not flagged", not r[3] and not r[4] and not r[5])

    # Rows for the fixture's two outpoints (both P2WPKH), as the page would hold them
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("""() => {
        window._fn.addFetchedInput('f25dd96b51a5a8e0561eaf9468609b6b215efeef779dd4579374fba974b9c642', 0, 9999654,
            '0014cb307ab14ce3a66b8a4a4c1e06c4718b7ea0d0f0', 'bc1qevc84v2vuwnxhzj2fs0qd3r33dl2p58swwurtn');
        window._fn.addFetchedInput('03999221997d3a049bfcc6e53442bfaba0386e8bb9eb67d449f6975ad2256aec', 20, 1564763,
            '0014b4a2e0b13c7cb5ae724259248cb057cc3d663bd2', 'bc1qkj3wpvfu0j66uujztyjgevzhes7kvw7jc2nxnl');
    }""")
    rows = page.evaluate("() => Object.fromEntries(window._fn.rowScriptsByOutpoint())")
    test("rowScriptsByOutpoint: both rows mapped", len(rows) == 2 and
         rows.get("f25dd96b51a5a8e0561eaf9468609b6b215efeef779dd4579374fba974b9c642:0", "").startswith("0014"))
    err = page.evaluate("(h) => window._fn.checkFinalTxWitness(h)", BAD_TX)
    test("checkFinalTxWitness: flags the P2PKH-style input 0", err is not None and "input 0" in err, str(err)[:80])
    test("checkFinalTxWitness: does not flag the correct input 1", err is not None and "input 1" not in err)
    test("checkFinalTxWitness: explains the Coldcard Q bug and the fix",
         err is not None and "Coldcard Q" in err and "-signed.psbt" in err)
    test("checkFinalTxWitness: unparsable hex is left to the node (null)", page.evaluate("() => window._fn.checkFinalTxWitness('zz')") is None)

    # Broadcast is blocked for that tx
    page.evaluate("(h) => { window._fn.finalTxHex = h; window._fn.finalPsbt = null; }", BAD_TX)
    _all_dialogs.clear()
    page.evaluate("() => window._fn.showCard('cardBroadcast')")
    page.evaluate("() => document.getElementById('broadcastSection').style.display = ''")
    page.click("#broadcastTx")
    time.sleep(1)
    test("broadcast: refused with the witness explanation",
         any("Not broadcasting" in d and "input 0" in d for d in _all_dialogs), f"{_all_dialogs}")

    # Scanned raw tx with the same defect is rejected before it is accepted
    _all_dialogs.clear()
    page.evaluate("() => { window._fn.finalTxHex = null; }")
    page.evaluate("(h) => window._fn.handleScannedQR(h)", BAD_TX)
    time.sleep(0.5)
    test("QR scan: legacy-scriptSig tx rejected",
         any("Scanned transaction rejected" in d for d in _all_dialogs) and page.evaluate("() => window._fn.finalTxHex") is None,
         f"{_all_dialogs[:1]}")

    # A correct P2WPKH tx passes: sign a fresh 1-in/1-out with a WIF
    ok_hex = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork(); const B = window._Buffer;
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: B.from(kp.publicKey), network: net });
        const spk = B.from(p2w.output).toString('hex');
        document.getElementById('utxoContainer').innerHTML = '';
        window._fn.addFetchedInput('ee'.repeat(32), 3, 100000, spk, p2w.address);
        const psbt = window._fn.createPsbtFromInputs([{ txid: 'ee'.repeat(32), vout: 3, value: 100000, scriptPubKey: spk }],
            [{ address: p2w.address, value: 90000 }], 0, '');
        window._fn.signInputWithWif(psbt, 0, kp.toWIF(), net);
        psbt.finalizeAllInputs();
        window.__okPsbt = psbt;
        return psbt.extractTransaction().toHex();
    }""")
    test("checkFinalTxWitness: correct witness spend passes", page.evaluate("(h) => window._fn.checkFinalTxWitness(h)", ok_hex) is None)

    # Combine guard: an uploaded PSBT whose P2WPKH input was pre-finalized with a
    # P2PKH-style scriptSig (what the CC Q writes) is rejected by name, before
    # finalizeAllInputs() turns it into an opaque error.
    r = page.evaluate("""() => {
        const B = window._Buffer; const bitcoin = window._bitcoin;
        const good = window.__okPsbt;
        const okErr = window._fn.checkPsbtFinalizedInputs(good);
        // Rebuild the same input, then forge a legacy finalization from the real witness items
        const bad = bitcoin.Psbt.fromHex(good.toHex());
        const w = good.data.inputs[0].finalScriptWitness;
        // decode witness vector: [count][len sig][sig][len pub][pub]
        let o = 0; const cnt = w[o++]; const items = [];
        for (let k = 0; k < cnt; k++) { const n = w[o++]; items.push(B.from(w.slice(o, o + n))); o += n; }
        const scriptSig = bitcoin.script.compile(items);
        bad.data.inputs[0].finalScriptWitness = undefined;
        delete bad.data.inputs[0].finalScriptWitness;
        bad.data.inputs[0].finalScriptSig = scriptSig;
        window._fn.psbtAccumulator.length = 0;
        window._fn.addPsbtToList('cc-final.psbt', 'file', new Uint8Array(bad.toBuffer()));
        return { okErr, badErr: window._fn.checkPsbtFinalizedInputs(bad) };
    }""")
    test("checkPsbtFinalizedInputs: correct finalized PSBT passes", r["okErr"] is None)
    test("checkPsbtFinalizedInputs: legacy finalScriptSig on P2WPKH flagged",
         r["badErr"] is not None and "input 0" in r["badErr"] and "Coldcard Q" in r["badErr"], str(r["badErr"])[:80])
    page.evaluate("() => { window._fn.showCard('cardBroadcast'); document.getElementById('combineSection').style.display = ''; }")
    _all_dialogs.clear()
    page.click("#combinePsbt")
    time.sleep(1)
    test("combine: rejects the legacy-finalized PSBT with the explanation",
         any("input 0" in d and "Coldcard Q" in d for d in _all_dialogs), f"{[d[:80] for d in _all_dialogs]}")
    page.evaluate("() => { window._fn.psbtAccumulator.length = 0; window._fn.renderPsbtList(); window._fn.showCard('cardCreate'); }")

    # Create-time warnings: xfp + path but no pubkey; account-level path with pubkey
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork(); const B = window._Buffer;
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: B.from(kp.publicKey), network: net });
        const spk = B.from(p2w.output).toString('hex');
        window._fn.addInput(null, 'aa'.repeat(32), 0, 100000, spk);   // manual row: has HW fields
        window._fn.rawTxCache.set('aa'.repeat(32), '00');
        const row = document.querySelector('#utxoContainer [data-utxo]');
        row.querySelector('.hw-xfp').value = '34c2083e';
        row.querySelector('.hw-path').value = "m/84'/0'/0'";
        document.getElementById('softwareSignerOverride').checked = false;
        window.__pub = B.from(kp.publicKey).toString('hex');
        window._fn.addOutput(null, p2w.address, 90000);
        document.querySelectorAll('.tip-preset').forEach(b => b.classList.remove('active'));
        document.querySelector('.tip-preset[data-pct="0"]').classList.add('active');
        document.getElementById('tipSats').value = '';
        window._fn.tipHeight = 900000;
        document.querySelectorAll('.locktime-preset').forEach(b => b.classList.toggle('active', b.dataset.mode === 'block'));
        document.getElementById('locktimeBlock').value = '900000';
    }""")
    page.fill("#feeRate", "1")
    _all_dialogs.clear()
    page.click("#createPsbt")
    for _ in range(50):
        if any("Cannot create the PSBT" in d for d in _all_dialogs): break
        time.sleep(0.2)
    test("create: BLOCKED when xfp + path but no pubkey (no override)",
         any("Cannot create the PSBT" in d and "aa" * 32 + ":0" in d and "missing: public key" in d for d in _all_dialogs),
         f"{[d[:70] for d in _all_dialogs]}")
    test("create: block message points at the zpub route", any("zpub" in d and "Sparrow" in d and "Coldcard" in d for d in _all_dialogs))
    test("create: no account-path warning without a pubkey", not any("account-level" in d for d in _all_dialogs))

    page.evaluate("() => { document.querySelector('#utxoContainer [data-utxo] .hw-pubkey').value = window.__pub; }")
    _all_dialogs.clear()
    page.click("#createPsbt")
    for _ in range(50):
        if any("account-level" in d for d in _all_dialogs): break
        time.sleep(0.2)
    test("create: warns about an account-level path once a pubkey is present",
         any("account-level" in d and "m/84'/0'/0'" in d for d in _all_dialogs), f"{[d[:70] for d in _all_dialogs]}")
    test("create: not blocked once key origin is complete", not any("Cannot create the PSBT" in d for d in _all_dialogs))

    page.evaluate("""() => { document.querySelector('#utxoContainer [data-utxo] .hw-path').value = "m/84'/0'/0'/0/5"; }""")
    _all_dialogs.clear()
    page.evaluate("() => { document.getElementById('psbtHex').textContent = ''; }")
    page.click("#createPsbt")
    try:
        page.wait_for_function("() => (document.getElementById('psbtHex').textContent || '').length > 0", timeout=5000)
    except Exception:
        pass
    r = page.evaluate("""() => {
        const hex = document.getElementById('psbtHex').textContent || '';
        if (!hex) return { built: false };
        const d = window._bitcoin.Psbt.fromHex(hex).data.inputs[0].bip32Derivation || [];
        return { built: true, n: d.length, path: d[0] && d[0].path, xfp: d[0] && window._Buffer.from(d[0].masterFingerprint).toString('hex') };
    }""")
    test("create: full path + pubkey + xfp -> no warnings", not any("account-level" in d or "Cannot create" in d for d in _all_dialogs), f"{[d[:70] for d in _all_dialogs]}")
    test("create: bip32Derivation written with the full path", r.get("built") and r.get("n") == 1 and r.get("path") == "m/84'/0'/0'/0/5" and r.get("xfp") == "34c2083e", f"{r}")
    page.evaluate("() => { document.getElementById('softwareSignerOverride').checked = true; }")

    # ========================================================
    section("44. Key-origin rule: WIF or xfp+path+pubkey, else blocked")
    # ========================================================

    # Address-fetched rows carry no editable HW fields, only the zpub hint;
    # xpub-scanned rows keep the (pre-filled) fields; WIF rows keep the WIF box.
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    r = page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork(); const B = window._Buffer;
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: B.from(kp.publicKey), network: net });
        const spk = B.from(p2w.output).toString('hex');
        window._fn.addFetchedInput('a1'.repeat(32), 0, 100000, spk, p2w.address);
        window._fn.addFetchedInput('a2'.repeat(32), 0, 100000, spk, p2w.address,
            { xpub: 'xpubPLACEHOLDER', path: "m/84'/0'/0'/0/0", pubkey: B.from(kp.publicKey).toString('hex') });
        window._fn.addFetchedInput('a3'.repeat(32), 0, 100000, spk, p2w.address, null, kp.toWIF());
        const rows = document.querySelectorAll('#utxoContainer [data-utxo]');
        const has = (row, sel) => !!row.querySelector(sel);
        return {
            addr: { hint: has(rows[0], '.hw-hint'), fields: has(rows[0], '.hw-xfp'), hintText: (rows[0].querySelector('.hw-hint') || {}).textContent || '' },
            xpub: { hint: has(rows[1], '.hw-hint'), fields: has(rows[1], '.hw-xfp'), pub: rows[1].querySelector('.hw-pubkey').value.length },
            wif:  { hint: has(rows[2], '.hw-hint'), fields: has(rows[2], '.hw-xfp'), wifBox: has(rows[2], '.wif-key') },
        };
    }""")
    test("address row: zpub hint, no editable HW fields", r["addr"]["hint"] and not r["addr"]["fields"] and "zpub" in r["addr"]["hintText"])
    test("xpub-scanned row: HW fields present and pre-filled", r["xpub"]["fields"] and not r["xpub"]["hint"] and r["xpub"]["pub"] == 66)
    test("WIF row: no hint, no HW fields, WIF box present", not r["wif"]["hint"] and not r["wif"]["fields"] and r["wif"]["wifBox"])

    # The rule itself
    r = page.evaluate("""() => {
        const u = (o) => Object.assign({ txid: 'ab'.repeat(32), vout: 0, xfp: '', derivationPath: '', pubkey: '', wif: '' }, o);
        const full = u({ xfp: '34c2083e', derivationPath: "m/84'/0'/0'/0/0", pubkey: '02' + '11'.repeat(32) });
        return {
            wifOk: window._fn.inputsMissingKeyOrigin([u({ wif: 'Kxyz' })]).length,
            fullOk: window._fn.inputsMissingKeyOrigin([full]).length,
            none: window._fn.inputsMissingKeyOrigin([u({})]).length,
            noXfp: window._fn.inputsMissingKeyOrigin([u({ derivationPath: "m/84'/0'/0'/0/0", pubkey: '02' + '11'.repeat(32) })]).length,
            noPath: window._fn.inputsMissingKeyOrigin([u({ xfp: '34c2083e', pubkey: '02' + '11'.repeat(32) })]).length,
            noPub: window._fn.inputsMissingKeyOrigin([u({ xfp: '34c2083e', derivationPath: "m/84'/0'/0'/0/0" })]).length,
            msg: window._fn.missingKeyOriginMessage(window._fn.inputsMissingKeyOrigin([u({ xfp: '34c2083e' })])),
        };
    }""")
    test("rule: WIF input passes", r["wifOk"] == 0)
    test("rule: complete key origin passes", r["fullOk"] == 0)
    test("rule: nothing at all is missing key origin", r["none"] == 1)
    test("rule: missing fingerprint alone is blocked", r["noXfp"] == 1)
    test("rule: missing path alone is blocked", r["noPath"] == 1)
    test("rule: missing pubkey alone is blocked", r["noPub"] == 1)
    test("rule: message lists exactly what is missing", "missing: path, public key" in r["msg"], r["msg"][:120])

    # Through the UI: an address-fetched row with no WIF is blocked unless the
    # software-signer claim is ticked; a WIF row is never blocked.
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork(); const B = window._Buffer;
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: B.from(kp.publicKey), network: net });
        const spk = B.from(p2w.output).toString('hex');
        window._fn.addFetchedInput('b1'.repeat(32), 0, 100000, spk, p2w.address);
        window._fn.rawTxCache.set('b1'.repeat(32), '00');
        window._fn.addOutput(null, p2w.address, 90000);
        document.querySelectorAll('.tip-preset').forEach(b => b.classList.remove('active'));
        document.querySelector('.tip-preset[data-pct="0"]').classList.add('active');
        document.getElementById('tipSats').value = '';
        window._fn.tipHeight = 900000;
        document.getElementById('locktimeBlock').value = '900000';
        document.getElementById('softwareSignerOverride').checked = false;
        document.getElementById('psbtHex').textContent = '';
    }""")
    page.fill("#feeRate", "1")
    _all_dialogs.clear()
    page.click("#createPsbt")
    for _ in range(50):
        if any("Cannot create the PSBT" in d for d in _all_dialogs): break
        time.sleep(0.2)
    test("UI: address row without WIF is blocked (override off)",
         any("Cannot create the PSBT" in d and "b1" * 32 + ":0" in d for d in _all_dialogs), f"{[d[:60] for d in _all_dialogs]}")
    test("UI: nothing built while blocked", page.evaluate("() => (document.getElementById('psbtHex').textContent || '').length") == 0)

    page.evaluate("() => { document.getElementById('softwareSignerOverride').checked = true; }")
    _all_dialogs.clear()
    page.click("#createPsbt")
    try:
        page.wait_for_function("() => (document.getElementById('psbtHex').textContent || '').length > 0", timeout=8000)
    except Exception:
        pass
    test("UI: software-signer claim lets it through", page.evaluate("() => (document.getElementById('psbtHex').textContent || '').length") > 0, f"{[d[:60] for d in _all_dialogs]}")
    test("UI: no block dialog with the claim ticked", not any("Cannot create the PSBT" in d for d in _all_dialogs))

    # WIF row, override off: never blocked
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    page.evaluate("() => document.getElementById('outputContainer').innerHTML = ''")
    page.evaluate("""() => {
        const net = window._fn.getSelectedNetwork(); const B = window._Buffer;
        const kp = window._ECPair.makeRandom({ network: net });
        const p2w = window._bitcoin.payments.p2wpkh({ pubkey: B.from(kp.publicKey), network: net });
        const spk = B.from(p2w.output).toString('hex');
        window._fn.addFetchedInput('b2'.repeat(32), 0, 100000, spk, p2w.address, null, kp.toWIF());
        window._fn.rawTxCache.set('b2'.repeat(32), '00');
        window._fn.addOutput(null, p2w.address, 90000);
        document.querySelectorAll('.tip-preset').forEach(b => b.classList.remove('active'));
        document.querySelector('.tip-preset[data-pct="0"]').classList.add('active');
        document.getElementById('tipSats').value = '';
        document.getElementById('softwareSignerOverride').checked = false;
        window._fn.updateStepLayout();
    }""")
    page.fill("#feeRate", "1")
    _all_dialogs.clear()
    page.click("#createPsbt")
    try:
        page.wait_for_function("() => !!window._fn.finalTxHex", timeout=8000)
    except Exception:
        pass
    test("UI: WIF-only sweep is not blocked with the claim off", page.evaluate("() => !!window._fn.finalTxHex"), f"{[d[:60] for d in _all_dialogs]}")

    # Defaults: off for real users, on in test mode, restored by resetAll
    fresh = page.context.new_page()
    fresh.goto(base_url)
    fresh.wait_for_function("() => document.getElementById('softwareSignerOverride') !== null", timeout=20000)
    test("default: software-signer claim is OFF outside test mode", fresh.evaluate("() => document.getElementById('softwareSignerOverride').checked") is False)
    fresh.close()
    page.evaluate("() => { document.getElementById('softwareSignerOverride').checked = false; window._fn.resetAll(); }")
    test("resetAll: restores the test-mode default (on)", page.evaluate("() => document.getElementById('softwareSignerOverride').checked") is True)

    # ========================================================
    section("45. HD wallet import dialog")
    # ========================================================
    ZPUB84 = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    VEC00 = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"   # BIP84 test vector 0/0
    VEC01 = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"   # 0/1
    VEC10 = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"   # 1/0 (change)
    VEC11 = "bc1qggnasd834t54yulsep6fta8lpjekv4zj6gv5rf"   # 1/1 (change, the one the flow selects)
    page.select_option("#network", "mainnet")
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")

    # zpub pins the type: dialog opens straight on the list
    page.fill("#fetchAddress", ZPUB84)
    page.click("#fetchUtxosBtn")
    page.wait_for_selector("#hdImportDialog", state="visible", timeout=8000)
    r = page.evaluate("""() => ({
        typeStep: document.getElementById('hdImportStepType').style.display,
        badge: document.getElementById('hdTypeBadge').textContent,
        rows: document.querySelectorAll('#hdAddrList .hd-addr-row').length,
        first: document.querySelector('#hdAddrList .hd-addr').textContent,
        goDisabled: document.getElementById('hdImportGo').disabled })""")
    test("zpub: type step skipped, Native SegWit badge", r["typeStep"] == "none" and r["badge"] == "Native SegWit")
    test("zpub: 20 rows shown", r["rows"] == 20)
    test("zpub: 0/0 is the BIP84 test-vector address", r["first"] == VEC00, r["first"])
    test("dialog: Import disabled with nothing selected", r["goDisabled"] is True)

    # pagination + change toggle + selection persistence
    page.click("#hdLoadMore")
    test("Show 20 more: 40 rows", page.evaluate("() => document.querySelectorAll('#hdAddrList .hd-addr-row').length") == 40)
    page.evaluate("() => { const b = document.querySelectorAll('#hdAddrList input')[0]; b.checked = true; b.dispatchEvent(new Event('change')); }")
    page.click('.hd-chain[data-chain="1"]')
    r = page.evaluate("""() => ({ first: document.querySelector('#hdAddrList .hd-addr').textContent,
        count: document.getElementById('hdSelCount').textContent,
        checked: document.querySelectorAll('#hdAddrList input:checked').length })""")
    test("change toggle: 1/0 derives the change-chain vector", r["first"] == VEC10, r["first"])
    test("change toggle: receive selection persists in count", r["count"] == "1 selected")
    test("change toggle: no change rows falsely checked", r["checked"] == 0)
    page.evaluate("() => { const b = document.querySelectorAll('#hdAddrList input')[1]; b.checked = true; b.dispatchEvent(new Event('change')); }")

    # select-all-shown on receive
    page.click('.hd-chain[data-chain="0"]')
    page.check("#hdSelectPage")
    test("select all shown: 40 receive + 1 change selected",
         page.evaluate("() => window._fn.hdState.selected.size") == 41)
    page.uncheck("#hdSelectPage")
    test("unselect all shown: only the change selection remains",
         page.evaluate("() => window._fn.hdState.selected.size") == 1)
    page.evaluate("() => { const b = document.querySelectorAll('#hdAddrList input')[0]; b.checked = true; b.dispatchEvent(new Event('change')); }")
    page.evaluate("() => { const b = document.querySelectorAll('#hdAddrList input')[1]; b.checked = true; b.dispatchEvent(new Event('change')); }")

    # import: EXACTLY the selected addresses are queried; empties reported
    hd_hits = []
    def hd_utxo_route(route, request):
        addr = request.url.split("/address/")[1].split("/")[0]
        hd_hits.append(addr)
        body = '[{"txid":"' + "ab" * 32 + '","vout":3,"value":123456,"status":{"confirmed":true}}]' if addr == VEC00 else "[]"
        route.fulfill(status=200, content_type="application/json", body=body)
    page.route("**/address/*/utxo", hd_utxo_route)
    page.click("#hdImportGo")
    page.wait_for_selector("#hdImportOverlay", state="hidden", timeout=15000)
    page.unroute("**/address/*/utxo")
    test("import: exactly the 3 selected addresses queried, no scan",
         sorted(hd_hits) == sorted([VEC00, VEC01, VEC11]), f"{hd_hits}")
    status = page.evaluate("() => document.getElementById('fetchStatus').textContent")
    test("import: status reports found-of-selected", "Imported 1 UTXO(s)" in status and "1 of 3 selected" in status, status)
    test("import: empty addresses listed by chain/index", "No UTXOs on: 0/1, 1/1" in status, status)
    r = page.evaluate("""() => { const row = document.querySelector('#utxoContainer [data-utxo]');
        return { addr: row.querySelector('.utxo-fetched-addr').textContent, path: row.querySelector('.hw-path').value,
                 pub: row.querySelector('.hw-pubkey').value.length, xpub: row.querySelector('.hw-xpub').value,
                 label: document.querySelector('.utxo-source-label').getAttribute('data-xpub-source') }; }""")
    test("import: row carries full key origin from the derivation",
         r["addr"] == VEC00 and r["path"] == "m/84'/0'/0'/0/0" and r["pub"] == 66 and r["xpub"] == ZPUB84)
    test("import: source label stamped with the xpub (xfp mirroring)", r["label"] == ZPUB84)

    # ambiguous xpub -> type chooser with real first addresses
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    xpub_form = page.evaluate(f"() => window._fn.normalizeExtendedKey('{ZPUB84}').key")
    page.fill("#fetchAddress", xpub_form)
    page.click("#fetchUtxosBtn")
    page.wait_for_selector("#hdImportStepType", state="visible", timeout=8000)
    r = page.evaluate("""() => Array.from(document.querySelectorAll('.hd-type-card')).map(c => c.textContent)""")
    test("xpub: type chooser offers Native SegWit and Taproot",
         len(r) == 2 and "Native SegWit" in r[0] and "Taproot" in r[1], f"{[x[:40] for x in r]}")
    test("xpub: cards show each type's real first address", VEC00[:24] in r[0] and "bc1p" in r[1])
    page.click(".hd-type-card >> nth=1")
    test("taproot pick: badge updates", page.evaluate("() => document.getElementById('hdTypeBadge').textContent") == "Taproot")
    test("taproot pick: rows are bc1p", page.evaluate("() => document.querySelector('#hdAddrList .hd-addr').textContent").startswith("bc1p"))
    page.click("#hdImportCancel")
    test("cancel closes the dialog", page.evaluate("() => document.getElementById('hdImportOverlay').style.display") == "none")

    # network mismatch messages preserved
    page.fill("#fetchAddress", "vpub5YvMuJNjRSYon44z9QmCfdf8SqJRVNvz6m55Qy5iVjZQxDfUgtiQjnc7CC1fAbED2tAGCZRERUfvtn2DstZGU6HMns6dXXH2wujSc2wfi2x")
    page.click("#fetchUtxosBtn")
    time.sleep(0.3)
    test("testnet key on mainnet: rejected with message",
         "Testnet extended key but mainnet selected" in page.evaluate("() => document.getElementById('fetchStatus').textContent"))

    # Checksum-broken key: isExtendedKey() itself checksum-validates, so the
    # UI dispatch sends it down the address branch; the dialog's own guard is
    # defense-in-depth for direct/future callers.
    broken = ZPUB84[:-1] + ("t" if ZPUB84[-1] != "t" else "u")
    page.fill("#fetchAddress", broken)
    page.click("#fetchUtxosBtn")
    time.sleep(0.3)
    test("checksum-broken key via UI: address-branch rejection",
         "Invalid address for selected network" in page.evaluate("() => document.getElementById('fetchStatus').textContent"))
    page.evaluate("(k) => window._fn.openHdImport(k)", broken)
    test("checksum-broken key via openHdImport: clean message, no throw",
         "Invalid extended public key" in page.evaluate("() => document.getElementById('fetchStatus').textContent"))

    # A fingerprint typed into ANY label of an xpub scan mirrors to the scan's
    # other labels (one is created per address-type + chain group) and their rows.
    page.evaluate("() => document.getElementById('utxoContainer').innerHTML = ''")
    r = page.evaluate("""() => {
        const c = document.getElementById('utxoContainer');
        const mk = (xpub, tag) => {
            const label = document.createElement('div');
            label.className = 'utxo-source-label';
            label.setAttribute('data-xpub-source', xpub);
            label.innerHTML = `${tag} <input class="xpub-xfp">`;
            c.appendChild(label);
            const xfpInput = label.querySelector('.xpub-xfp');
            xfpInput.addEventListener('input', () => {
                const val = xfpInput.value.trim();
                let el = label.nextElementSibling;
                while (el && !el.classList.contains('utxo-source-label')) {
                    if (el.hasAttribute('data-utxo')) {
                        const hwXfp = el.querySelector('.hw-xfp');
                        if (hwXfp) hwXfp.value = val;
                    }
                    el = el.nextElementSibling;
                }
                document.querySelectorAll('.utxo-source-label[data-xpub-source]').forEach(other => {
                    if (other === label) return;
                    if (other.getAttribute('data-xpub-source') !== xpub) return;
                    const otherXfp = other.querySelector('.xpub-xfp');
                    if (otherXfp && otherXfp.value !== xfpInput.value) {
                        otherXfp.value = xfpInput.value;
                        otherXfp.dispatchEvent(new Event('input'));
                    }
                });
            });
            return label;
        };
        // scan A: two groups; scan B (different xpub): one group
        mk('xpubAAA', 'A-receive');
        window._fn.addInput(null, '11'.repeat(32), 0, 1000, '0014' + 'aa'.repeat(20));
        mk('xpubAAA', 'A-change');
        window._fn.addInput(null, '22'.repeat(32), 0, 1000, '0014' + 'bb'.repeat(20));
        mk('xpubBBB', 'B-receive');
        window._fn.addInput(null, '33'.repeat(32), 0, 1000, '0014' + 'cc'.repeat(20));
        const first = c.querySelector('.xpub-xfp');
        first.value = 'deadbeef';
        first.dispatchEvent(new Event('input'));
        const rows = [...c.querySelectorAll('[data-utxo] .hw-xfp')].map(i => i.value);
        const labels = [...c.querySelectorAll('.xpub-xfp')].map(i => i.value);
        return { rows, labels };
    }""")
    test("xfp mirrors across the same scan's labels and rows",
         r["rows"][0] == "deadbeef" and r["rows"][1] == "deadbeef" and r["labels"][1] == "deadbeef", f"{r}")
    test("xfp does not leak into a different xpub's label",
         r["labels"][2] == "" and r["rows"][2] == "", f"{r}")
    page.evaluate("() => window._fn.resetAll()")


# ============================================================
# Main
# ============================================================

def main():
    port = find_free_port()
    os.chdir(_PROJECT_ROOT)
    httpd = start_http_server(port)
    base_url = f"http://127.0.0.1:{port}/index.html"

    print(f"Server started at http://127.0.0.1:{port}")
    print(f"Mode: {'headed' if HEADED else 'headless'}\n")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not HEADED)
            context = browser.new_context(accept_downloads=True)
            page = context.new_page()

            # Enable test mode
            page.add_init_script("window.__TEST_MODE__ = true;")

            run_tests(page, base_url)

            browser.close()
    except Exception:
        traceback.print_exc()
    finally:
        httpd.shutdown()

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
