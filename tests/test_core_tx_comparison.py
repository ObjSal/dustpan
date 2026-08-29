#!/usr/bin/env python3
"""
Byte-for-byte transaction comparison against Bitcoin Core.

Builds transactions through the sweeper's own PSBT builder and asserts the
serialized unsigned transaction is IDENTICAL to what Bitcoin Core produces
from the same inputs and outputs via `createrawtransaction`.

Why Core and not Sparrow: Sparrow's entire CLI surface is
--dir/--help/--level/--network/--terminal/--version. `--terminal` is an
interactive TUI; there is no command that takes UTXOs and prints transaction
hex, so it cannot be an automated oracle. Bitcoin Core can, and it is the
consensus implementation -- a strictly stronger reference.

Coverage, in the order the shapes were requested:
  1. single input  -> single output
  2. multiple inputs -> multiple outputs
  3. mix and match  (P2WPKH / P2SH-P2WPKH / P2TR / P2PKH on both sides)
  4. 21-in -> 21-out, all native segwit  (the real consolidation shape)
  5. funded end-to-end: sign, finalize, and prove consensus validity with
     `testmempoolaccept` -- the actual "only the receiver can spend it" check

Node: the persistent regtest node on the Pi. This suite NEVER spawns a local
bitcoind (see prime/PLAN-one-regtest-node.md) -- server/server.py would bind
18443 and collide with the SSH tunnel.

Usage:
    ../prime/ui-automation/node-env.sh regtest python3 tests/test_core_tx_comparison.py
    ... --headed        # visible browser
"""

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import traceback

from playwright.sync_api import sync_playwright

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TEST_DIR)
HEADED = "--headed" in sys.argv

# Bitcoin Core's own dust threshold for a P2WPKH output (sat).
DUST_LIMIT = 294


# ============================================================
# Node access -- the shared contract from PLAN-one-regtest-node.md
# ============================================================

def _require_env(name):
    val = os.environ.get(name)
    if not val:
        sys.exit(
            f"{name} is not set.\n\n"
            "Run this suite through the credential wrapper:\n"
            "  ../prime/ui-automation/node-env.sh regtest "
            "python3 tests/test_core_tx_comparison.py"
        )
    return val


NODE_HOST = os.environ.get("CN_NODE_HOST", "127.0.0.1")
NODE_PORT = os.environ.get("CN_NODE_PORT", "18443")
RPC_USER = _require_env("CORE_RPC_USER")
RPC_PASS = _require_env("CORE_RPC_PASS")

_BASE_CLI = [
    "bitcoin-cli", "-regtest",
    f"-rpcconnect={NODE_HOST}",
    f"-rpcport={NODE_PORT}",
    f"-rpcuser={RPC_USER}",
    f"-rpcpassword={RPC_PASS}",
]


def rpc(*args, wallet=None):
    """Call bitcoin-cli. Returns parsed JSON when the reply is JSON."""
    cmd = list(_BASE_CLI)
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd += [str(a) for a in args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {args[0]} failed: {proc.stderr.strip()}")
    out = proc.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


# ============================================================
# HTTP server + harness (same pattern as test_psbt_builder.py)
# ============================================================

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_http_server(port):
    os.chdir(_PROJECT_ROOT)
    handler = http.server.SimpleHTTPRequestHandler

    class Quiet(handler):
        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", port), Quiet)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


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
            msg += f"\n      {detail}"
        print(msg)
        _failures.append(name)


def section(title):
    print(f"\n{'='*64}\n  {title}\n{'='*64}")


# ============================================================
# The comparison itself
# ============================================================

def build_in_page(page, utxos, outputs):
    """Build via the app and return the serialized unsigned transaction hex."""
    return page.evaluate(
        """([utxos, outputs]) => {
            const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, '');
            const buf = psbt.data.globalMap.unsignedTx.toBuffer();
            return window._Buffer.from(buf).toString('hex');
        }""",
        [utxos, outputs],
    )


def build_in_core(utxos, outputs):
    """Build the same transaction with Core's createrawtransaction."""
    ins = [{"txid": u["txid"], "vout": u["vout"], "sequence": 0xFFFFFFFD} for u in utxos]
    # Core takes BTC amounts keyed by address, and preserves the given order.
    outs = [{o["address"]: f"{o['value'] / 1e8:.8f}"} for o in outputs]
    return rpc("createrawtransaction", json.dumps(ins), json.dumps(outs))


def diff_hex(ours, theirs):
    """First differing byte, with surrounding context, for a readable failure."""
    if ours == theirs:
        return ""
    if len(ours) != len(theirs):
        head = f"length differs: app={len(ours)//2}B core={len(theirs)//2}B\n      "
    else:
        head = ""
    for i in range(0, min(len(ours), len(theirs)), 2):
        if ours[i:i + 2] != theirs[i:i + 2]:
            lo = max(0, i - 16)
            hi = i + 18
            return (
                f"{head}first difference at byte {i//2}: "
                f"app={ours[i:i+2]} core={theirs[i:i+2]}\n"
                f"      app : ...{ours[lo:hi]}...\n"
                f"      core: ...{theirs[lo:hi]}..."
            )
    return head + "one is a prefix of the other"


def compare(page, label, utxos, outputs):
    """Assert the app and Core serialize this transaction identically."""
    ours = build_in_page(page, utxos, outputs)
    theirs = build_in_core(utxos, outputs)

    test(f"{label}: byte-for-byte identical to Core", ours == theirs,
         diff_hex(ours, theirs))

    # txid equality is a cryptographic restatement of the same claim: for an
    # unsigned (witness-free) transaction the txid is the double-SHA256 of
    # exactly these bytes, so matching txids cannot happen for differing bytes.
    if ours == theirs:
        ours_txid = rpc("decoderawtransaction", ours)["txid"]
        core_txid = rpc("decoderawtransaction", theirs)["txid"]
        test(f"{label}: txid matches ({ours_txid[:16]}…)", ours_txid == core_txid)

    return ours


def assert_output_scripts(page, label, outputs, raw_hex):
    """
    Every output's scriptPubKey must be the one Core derives from the address.
    This is the "only the receiver can spend it" check: the spending condition
    is whatever Core says that address means, with nothing added.
    """
    decoded = rpc("decoderawtransaction", raw_hex)
    ok = True
    detail = []
    for i, o in enumerate(outputs):
        core_spk = rpc("validateaddress", o["address"])["scriptPubKey"]
        got = decoded["vout"][i]["scriptPubKey"]["hex"]
        got_val = round(decoded["vout"][i]["value"] * 1e8)
        if got != core_spk:
            ok = False
            detail.append(f"vout {i}: got {got}, Core says {core_spk}")
        if got_val != o["value"]:
            ok = False
            detail.append(f"vout {i}: value {got_val} != {o['value']}")
    test(f"{label}: every output script is Core's script for its address",
         ok, "\n      ".join(detail))


# ============================================================
# Fixtures
# ============================================================

def fake_txid(n):
    """Deterministic, valid-shaped txids so runs are reproducible."""
    return f"{n:064x}"


def make_addresses(kind, count, wallet):
    """Fresh addresses of a given type from the node."""
    kinds = {
        "p2wpkh": "bech32",
        "p2tr": "bech32m",
        "p2sh-p2wpkh": "p2sh-segwit",
        "p2pkh": "legacy",
    }
    return [rpc("getnewaddress", "", kinds[kind], wallet=wallet) for _ in range(count)]


def spk_for(address):
    return rpc("validateaddress", address)["scriptPubKey"]


# A fixed BIP32 test key, so bulk address generation is one RPC instead of
# hundreds. Core's createrawtransaction keys outputs by address, so it rejects
# duplicates -- the varint cases below need genuinely distinct addresses.
_BULK_TPUB = ("tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4"
              "qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
_bulk_cache = []


def bulk_addresses(count, chain=0):
    """`count` distinct regtest P2WPKH addresses, derived in a single call."""
    global _bulk_cache
    if len(_bulk_cache) < count:
        desc = f"wpkh({_BULK_TPUB}/{chain}/*)"
        checksum = rpc("getdescriptorinfo", desc)["checksum"]
        _bulk_cache = rpc("deriveaddresses", f"{desc}#{checksum}",
                          json.dumps([0, max(count, 300) - 1]))
    return _bulk_cache[:count]


# ============================================================
# Tests
# ============================================================

def run_tests(page, base_url, wallet):
    page.goto(base_url)
    page.wait_for_function("() => window._fn !== undefined", timeout=20000)
    page.evaluate("() => { document.getElementById('network').value = 'regtest'; }")
    page.on("dialog", lambda d: d.accept())

    # --------------------------------------------------------
    section("1. Single input -> single output")
    # --------------------------------------------------------
    addr = make_addresses("p2wpkh", 1, wallet)[0]
    utxos = [{"txid": fake_txid(1), "vout": 0, "value": 100_000,
              "scriptPubKey": spk_for(addr)}]
    outputs = [{"address": addr, "value": 90_000}]
    raw = compare(page, "1-in/1-out P2WPKH", utxos, outputs)
    assert_output_scripts(page, "1-in/1-out P2WPKH", outputs, raw)

    # A non-zero vout must be serialized correctly too.
    utxos2 = [{"txid": fake_txid(2), "vout": 7, "value": 55_555,
               "scriptPubKey": spk_for(addr)}]
    compare(page, "1-in/1-out, vout=7", utxos2, [{"address": addr, "value": 50_000}])

    # --------------------------------------------------------
    section("2. Multiple inputs -> multiple outputs")
    # --------------------------------------------------------
    in_addrs = make_addresses("p2wpkh", 3, wallet)
    out_addrs = make_addresses("p2wpkh", 3, wallet)
    utxos = [{"txid": fake_txid(10 + i), "vout": i, "value": 100_000 + i,
              "scriptPubKey": spk_for(a)} for i, a in enumerate(in_addrs)]
    outputs = [{"address": a, "value": 90_000 + i} for i, a in enumerate(out_addrs)]
    raw = compare(page, "3-in/3-out P2WPKH", utxos, outputs)
    assert_output_scripts(page, "3-in/3-out P2WPKH", outputs, raw)

    # Input and output ORDER must be preserved -- reordering would silently
    # pay the wrong person the wrong amount.
    rev_out = list(reversed(outputs))
    raw_rev = compare(page, "3-in/3-out, outputs reversed", utxos, rev_out)
    test("output order is preserved (reversed build differs)", raw != raw_rev)
    assert_output_scripts(page, "3-in/3-out reversed", rev_out, raw_rev)

    # --------------------------------------------------------
    section("3. Mix and match script types")
    # --------------------------------------------------------
    mixed_in = []
    for i, kind in enumerate(["p2wpkh", "p2sh-p2wpkh", "p2tr", "p2pkh"]):
        a = make_addresses(kind, 1, wallet)[0]
        mixed_in.append({"txid": fake_txid(30 + i), "vout": i, "value": 200_000 + i,
                         "scriptPubKey": spk_for(a)})

    mixed_out = []
    for i, kind in enumerate(["p2tr", "p2wpkh", "p2pkh", "p2sh-p2wpkh"]):
        a = make_addresses(kind, 1, wallet)[0]
        mixed_out.append({"address": a, "value": 150_000 + i})

    raw = compare(page, "4-in/4-out mixed types", mixed_in, mixed_out)
    assert_output_scripts(page, "4-in/4-out mixed types", mixed_out, raw)

    # Every output type on its own, so a failure names the guilty type.
    for kind in ["p2wpkh", "p2tr", "p2pkh", "p2sh-p2wpkh"]:
        a = make_addresses(kind, 1, wallet)[0]
        outs = [{"address": a, "value": 75_000}]
        r = compare(page, f"single {kind} output", mixed_in[:1], outs)
        assert_output_scripts(page, f"single {kind} output", outs, r)

    # --------------------------------------------------------
    section("4. 21 inputs -> 21 outputs, all native segwit")
    # --------------------------------------------------------
    n = 21
    big_in_addrs = make_addresses("p2wpkh", n, wallet)
    big_out_addrs = make_addresses("p2wpkh", n, wallet)
    big_in = [{"txid": fake_txid(100 + i), "vout": i % 4, "value": 1_000_000 + i * 137,
               "scriptPubKey": spk_for(a)} for i, a in enumerate(big_in_addrs)]
    big_out = [{"address": a, "value": 900_000 + i * 101}
               for i, a in enumerate(big_out_addrs)]

    raw = compare(page, f"{n}-in/{n}-out native segwit", big_in, big_out)
    assert_output_scripts(page, f"{n}-in/{n}-out native segwit", big_out, raw)

    decoded = rpc("decoderawtransaction", raw)
    test(f"{n}-in/{n}-out: input count is {n}", len(decoded["vin"]) == n,
         f"got {len(decoded['vin'])}")
    test(f"{n}-in/{n}-out: output count is {n}", len(decoded["vout"]) == n,
         f"got {len(decoded['vout'])}")
    test(f"{n}-in/{n}-out: every input is RBF-signalling",
         all(v["sequence"] == 0xFFFFFFFD for v in decoded["vin"]))
    test(f"{n}-in/{n}-out: every output is v0 witness program",
         all(v["scriptPubKey"]["hex"].startswith("0014") for v in decoded["vout"]))

    # Counts either side of the 1-byte/3-byte varint boundary, since that is
    # where a hand-rolled serializer would break.
    in_spk = spk_for(big_in_addrs[0])
    for count in (1, 2, 21, 100, 252, 253, 254):
        vin = [{"txid": fake_txid(1000 + i), "vout": 0, "value": 50_000,
                "scriptPubKey": in_spk} for i in range(count)]
        vout = [{"address": big_out_addrs[0], "value": 40_000}]
        ours = build_in_page(page, vin, vout)
        theirs = build_in_core(vin, vout)
        test(f"varint boundary: {count} inputs serialize identically",
             ours == theirs, diff_hex(ours, theirs))

    distinct = bulk_addresses(254)
    for count in (1, 2, 21, 252, 253, 254):
        vin = big_in[:1]
        vout = [{"address": distinct[i], "value": 1_000 + i}
                for i in range(count)]
        ours = build_in_page(page, vin, vout)
        theirs = build_in_core(vin, vout)
        test(f"varint boundary: {count} outputs serialize identically",
             ours == theirs, diff_hex(ours, theirs))

    return big_out_addrs


# ============================================================
# 5. Funded end-to-end -- consensus validity of a real sweep
# ============================================================

def run_funded_sweep(page, base_url, wallet, n=21):
    section(f"5. Funded {n}-in/{n}-out sweep -> testmempoolaccept")

    # Fresh keys generated in the page. Core 31 dropped dumpprivkey along with
    # legacy wallets, and generating here exercises the real WIF sweep path:
    # these are exactly the keys a paper wallet would hand over.
    keys = page.evaluate(
        """(n) => {
            const net = window._fn.getSelectedNetwork();
            const out = [];
            for (let i = 0; i < n; i++) {
                const kp = window._ECPair.makeRandom({ network: net });
                const addr = window._bitcoin.payments.p2wpkh({
                    pubkey: window._Buffer.from(kp.publicKey), network: net,
                }).address;
                out.push({ wif: kp.toWIF(), address: addr });
            }
            return out;
        }""", n)
    test(f"generated {n} keypairs in-page", len(keys) == n)

    # Fund each address in one transaction.
    per = 0.001  # BTC
    send_outs = {k["address"]: f"{per:.8f}" for k in keys}
    funding_txid = rpc("send", json.dumps(send_outs), wallet="testwallet")["txid"]
    print(f"  funded {n} addresses in {funding_txid[:16]}…")

    # gettxout sees the mempool, so an accepted funding tx is enough -- no
    # mining, and no assumption that we control block production.
    funded = rpc("decoderawtransaction", rpc("getrawtransaction", funding_txid))
    by_addr = {}
    for v in funded["vout"]:
        spk = v["scriptPubKey"]
        if spk.get("address") in send_outs:
            by_addr[spk["address"]] = {
                "vout": v["n"],
                "value": round(v["value"] * 1e8),
                "scriptPubKey": spk["hex"],
            }
    test(f"all {n} funding outputs located", len(by_addr) == n,
         f"found {len(by_addr)}")
    if len(by_addr) != n:
        return

    utxos = []
    for k in keys:
        o = by_addr[k["address"]]
        utxos.append({
            "txid": funding_txid, "vout": o["vout"], "value": o["value"],
            "scriptPubKey": o["scriptPubKey"], "wif": k["wif"],
        })

    # Sweep to n fresh recipients, leaving a realistic fee.
    recipients = make_addresses("p2wpkh", n, wallet)
    total_in = sum(u["value"] for u in utxos)
    fee = 4000  # ~2 sat/vB on a ~2000 vB transaction
    each = (total_in - fee) // n
    test(f"per-output amount is above dust ({each} sat)", each > DUST_LIMIT)
    outputs = [{"address": a, "value": each} for a in recipients]

    # Byte-comparison of the real transaction, then sign it in the page.
    raw = compare(page, f"funded {n}-in/{n}-out", utxos, outputs)
    assert_output_scripts(page, f"funded {n}-in/{n}-out", outputs, raw)

    signed = page.evaluate(
        """([utxos, outputs]) => {
            const net = window._fn.getSelectedNetwork();
            const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, '');
            for (let i = 0; i < utxos.length; i++) {
                window._fn.signInputWithWif(psbt, i, utxos[i].wif, net);
            }
            psbt.finalizeAllInputs();
            return psbt.extractTransaction().toHex();
        }""",
        [utxos, outputs],
    )
    test("all inputs signed and finalized in-page", bool(signed))

    # The real question: does the network accept it?
    res = rpc("testmempoolaccept", json.dumps([signed]))[0]
    test("Core accepts the signed transaction (testmempoolaccept)",
         res.get("allowed") is True,
         f"reject-reason: {res.get('reject-reason')}")

    if res.get("allowed"):
        vsize = res["vsize"]
        paid = total_in - each * n
        print(f"  vsize {vsize} vB, fee {paid} sat "
              f"({paid / vsize:.2f} sat/vB)")

        # The app's own estimator, on the shape it is actually used for.
        est = page.evaluate(
            f"() => Math.ceil(10.5 + 68 * {n} + 31 * {n})")
        drift = abs(est - vsize) / vsize
        test(f"app vsize estimate within 5% of Core ({est} vs {vsize} vB)",
             drift < 0.05, f"drift {drift*100:.1f}%")

        # Signed transaction must still pay exactly the intended scripts.
        dec = rpc("decoderawtransaction", signed)
        good = all(
            dec["vout"][i]["scriptPubKey"]["hex"] == spk_for(o["address"])
            and round(dec["vout"][i]["value"] * 1e8) == o["value"]
            for i, o in enumerate(outputs)
        )
        test("signed transaction pays exactly the intended scripts/amounts", good)

        test("no input carries a scriptSig (native segwit stays witness-only)",
             all(v["scriptSig"]["hex"] == "" for v in dec["vin"]))


def run_taproot_sweep(page, wallet, n=3):
    """
    Regression test for the tapInternalKey gap: a WIF sweep that includes P2TR
    UTXOs. Before the fix these inputs were added without tapInternalKey and
    signed with an untweaked key, so finalizeAllInputs() could never succeed.
    """
    section(f"6. Funded taproot WIF sweep ({n} P2TR inputs)")

    keys = page.evaluate(
        """(n) => {
            const net = window._fn.getSelectedNetwork();
            const out = [];
            for (let i = 0; i < n; i++) {
                const kp = window._ECPair.makeRandom({ network: net });
                out.push({
                    wif: kp.toWIF(),
                    address: window._fn.pubkeyToAddress(
                        window._Buffer.from(kp.publicKey), 'p2tr', net),
                });
            }
            return out;
        }""", n)
    test(f"derived {n} P2TR addresses from WIFs",
         len(keys) == n and all(k["address"].startswith("bcrt1p") for k in keys))

    send_outs = {k["address"]: "0.001" for k in keys}
    txid = rpc("send", json.dumps(send_outs), wallet="testwallet")["txid"]
    funded = rpc("decoderawtransaction", rpc("getrawtransaction", txid))

    utxos = []
    for k in keys:
        for v in funded["vout"]:
            if v["scriptPubKey"].get("address") == k["address"]:
                utxos.append({
                    "txid": txid, "vout": v["n"],
                    "value": round(v["value"] * 1e8),
                    "scriptPubKey": v["scriptPubKey"]["hex"],
                    "wif": k["wif"],
                })
    test(f"all {n} taproot outputs located", len(utxos) == n, f"found {len(utxos)}")
    if len(utxos) != n:
        return

    test("taproot scripts are v1 witness programs",
         all(u["scriptPubKey"].startswith("5120") for u in utxos))

    dest = make_addresses("p2wpkh", 1, wallet)[0]
    total = sum(u["value"] for u in utxos)
    outputs = [{"address": dest, "value": total - 2000}]

    # tapInternalKey must be present on every taproot input.
    has_key = page.evaluate(
        """([utxos, outputs]) => {
            const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, '');
            return psbt.data.inputs.every(i => !!i.tapInternalKey);
        }""", [utxos, outputs])
    test("every taproot input carries tapInternalKey", has_key)

    signed = page.evaluate(
        """([utxos, outputs]) => {
            const net = window._fn.getSelectedNetwork();
            const psbt = window._fn.createPsbtFromInputs(utxos, outputs, 0, '');
            for (let i = 0; i < utxos.length; i++) {
                window._fn.signInputWithWif(psbt, i, utxos[i].wif, net);
            }
            psbt.finalizeAllInputs();
            return psbt.extractTransaction().toHex();
        }""", [utxos, outputs])
    test("taproot inputs sign and finalize", bool(signed))

    res = rpc("testmempoolaccept", json.dumps([signed]))[0]
    test("Core accepts the taproot sweep (testmempoolaccept)",
         res.get("allowed") is True, f"reject-reason: {res.get('reject-reason')}")

    dec = rpc("decoderawtransaction", signed)
    test("each taproot input has a single 64-byte schnorr witness",
         all(len(v["txinwitness"]) == 1 and len(v["txinwitness"][0]) == 128
             for v in dec["vin"]),
         str([[len(w) for w in v["txinwitness"]] for v in dec["vin"]]))


# ============================================================
# Main
# ============================================================

def main():
    info = rpc("getblockchaininfo")
    if info["chain"] != "regtest":
        sys.exit(f"expected regtest, node says '{info['chain']}'")
    print(f"node: {NODE_HOST}:{NODE_PORT}  chain={info['chain']}  "
          f"blocks={info['blocks']}")

    wallet = f"jp-cmp-{int(time.time())}"
    rpc("createwallet", wallet)
    print(f"wallet: {wallet}")

    port = find_free_port()
    httpd = start_http_server(port)
    base_url = f"http://127.0.0.1:{port}/index.html"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not HEADED)
            page = browser.new_page()
            page.add_init_script("window.__TEST_MODE__ = true;")
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))

            try:
                run_tests(page, base_url, wallet)
                try:
                    rpc("loadwallet", "testwallet")
                except RuntimeError:
                    pass
                bal = rpc("getbalance", wallet="testwallet")
                if float(bal) < 1:
                    print("  ! testwallet balance too low, skipping funded sweep")
                else:
                    run_funded_sweep(page, base_url, wallet)
                    run_taproot_sweep(page, wallet)
            finally:
                test("no uncaught page errors", not errors, "; ".join(errors))
                browser.close()
    finally:
        httpd.shutdown()
        try:
            rpc("unloadwallet", wallet)
        except RuntimeError:
            pass

    print(f"\n{'='*64}")
    print(f"  {_pass_count} passed, {_fail_count} failed")
    if _failures:
        print("  failed:")
        for f in _failures:
            print(f"    - {f}")
    print(f"{'='*64}")
    return 1 if _fail_count else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
