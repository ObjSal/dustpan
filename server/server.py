"""
Local development server for Dustpan (formerly Bitcoin Address Sweeper).

Serves the HTML frontend and provides mempool.space-compatible API endpoints.
Three modes:

  - static (default): plain file server, no node. mainnet/testnet4 use
    mempool.space directly from the browser.
  - --regtest: spawns and OWNS a throwaway Bitcoin Core regtest node
    (RegtestNode below), with a faucet and auto-mining, for local dev/tests.
  - --connect [host[:rpcport]]: bridges an EXISTING bitcoind (any chain)
    that you already run -- for node-runners without electrs/Fulcrum. No
    node is spawned, owned, or torn down; every call shells out to
    bitcoin-cli against the given RPC endpoint. UTXO lookups use
    scantxoutset, which is synchronous and can take MINUTES on a mainnet
    node's full UTXO set (there's no address index). This mode is for a
    normal desktop browser -- Tor Browser on Tails cannot reach localhost
    at all, so it can never use it.

Requires:
  - Bitcoin Core (bitcoind + bitcoin-cli) in PATH (only for --regtest/--connect)

Usage:
    python3 server/server.py [port] [--regtest]
    python3 server/server.py [port] --connect [host[:rpcport]] \
        [--chain {mainnet,testnet4,regtest}] \
        [--rpccookie FILE | --rpcuser USER --rpcpassword PASS]
"""

import argparse
import json
import math
import os
import socket
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Resolve paths relative to this script
_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_DIR)

# Active node/mode -- set once at startup by run_server(), read by handlers.
_regtest_node = None     # RegtestNode, when _mode == "regtest"
_connect_node = None     # ConnectNode, when _mode == "connect"
_mode = "static"         # "static" | "regtest" | "connect"


# ============================================================
# Managed regtest node
# ============================================================

class RegtestNode:
    """Manage a Bitcoin Core regtest node for local development/testing."""

    def __init__(self):
        self.datadir = tempfile.mkdtemp(prefix="psbt_regtest_")
        self.process = None
        self.rpc_port = self._pick_rpc_port()
        self.wallet_name = "psbt_faucet"

    @staticmethod
    def _pick_rpc_port():
        """
        18443 unless something else (e.g. an SSH tunnel to another regtest
        node) already holds it, in which case a free port. Clients read the
        actual port from /api/health, so nothing else needs to know.
        Override with PSBT_REGTEST_RPC_PORT.
        """
        env = os.environ.get("PSBT_REGTEST_RPC_PORT")
        if env:
            return int(env)
        for candidate in (18443, 0):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("127.0.0.1", candidate))
                    return s.getsockname()[1]
            except OSError:
                continue
        return 18443

    def _cli(self, *args, wallet=None, timeout=30):
        """Run bitcoin-cli with managed node credentials."""
        cmd = [
            "bitcoin-cli",
            f"-datadir={self.datadir}",
            "-regtest",
            f"-rpcport={self.rpc_port}",
            "-rpcuser=test",
            "-rpcpassword=test",
        ]
        if wallet:
            cmd.append(f"-rpcwallet={wallet}")
        cmd.extend(args)

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            raise RuntimeError(
                f"bitcoin-cli {' '.join(args)} timed out after {timeout}s"
            )

        stdout_str = stdout.decode("utf-8", errors="replace").strip()
        stderr_str = stderr.decode("utf-8", errors="replace").strip()

        if proc.returncode != 0:
            raise RuntimeError(
                f"bitcoin-cli {' '.join(args)} failed (rc={proc.returncode}): "
                f"{stderr_str}"
            )
        return stdout_str

    def _cli_json(self, *args, wallet=None, timeout=30):
        """Run bitcoin-cli and parse JSON output."""
        return json.loads(self._cli(*args, wallet=wallet, timeout=timeout))

    def start(self):
        """Start bitcoind in regtest mode with a funded wallet."""
        print(f"  Starting bitcoind (datadir: {self.datadir})...")

        # Detect version
        try:
            ver_out = subprocess.run(
                ["bitcoind", "--version"], capture_output=True, text=True,
                timeout=10,
            ).stdout
            print(f"  {ver_out.strip().splitlines()[0]}")
        except Exception:
            pass

        # Write bitcoin.conf
        conf_path = os.path.join(self.datadir, "bitcoin.conf")
        with open(conf_path, "w") as f:
            f.write("regtest=1\nserver=1\ntxindex=1\n")
            f.write("rpcuser=test\nrpcpassword=test\n")
            f.write("dnsseed=0\nlisten=0\nlistenonion=0\n")
            f.write("[regtest]\n")
            f.write(f"rpcport={self.rpc_port}\n")
            f.write("fallbackfee=0.00001\n")

        # macOS fix: concrete file descriptor limit
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY or soft < 1024:
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))

        # Start bitcoind
        self.process = subprocess.Popen(
            ["bitcoind", f"-datadir={self.datadir}", "-regtest", "-daemon=0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Wait for ready
        for i in range(30):
            try:
                info = self._cli("getblockchaininfo", timeout=10)
                if "regtest" in info:
                    print("  bitcoind is ready.")
                    break
            except RuntimeError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("bitcoind failed to start within 30 seconds")

        # Create descriptor wallet
        try:
            self._cli("-named", "createwallet",
                      f"wallet_name={self.wallet_name}",
                      "descriptors=true")
            print("  Created descriptor wallet.")
        except RuntimeError as e:
            if "already exists" in str(e):
                try:
                    self._cli("loadwallet", self.wallet_name)
                    print("  Loaded existing wallet.")
                except RuntimeError as e2:
                    if "already loaded" in str(e2):
                        print("  Wallet already loaded.")
                    else:
                        raise
            else:
                raise

        # Mine initial blocks (101 for mature coinbase)
        mining_addr = self._cli("getnewaddress", wallet=self.wallet_name)
        self._cli("generatetoaddress", "101", mining_addr,
                  wallet=self.wallet_name)
        print("  Mined 101 blocks (coinbase mature).")

    def stop(self):
        """Stop bitcoind and clean up temp datadir."""
        if self.process:
            try:
                self._cli("stop", timeout=10)
                self.process.wait(timeout=15)
            except Exception:
                try:
                    self.process.kill()
                    self.process.wait(timeout=5)
                except Exception:
                    pass
        if os.path.exists(self.datadir):
            shutil.rmtree(self.datadir, ignore_errors=True)
        print("  bitcoind stopped and cleaned up.")

    def fund_address(self, address, amount_btc="1.0"):
        """Fund an address: create tx -> sign -> broadcast -> mine 1 block."""
        outputs_json = json.dumps([{address: float(amount_btc)}])
        raw_hex = self._cli("createrawtransaction", "[]", outputs_json,
                            wallet=self.wallet_name)
        funded_json = self._cli("fundrawtransaction", raw_hex,
                                wallet=self.wallet_name)
        funded = json.loads(funded_json)
        signed_json = self._cli("signrawtransactionwithwallet", funded["hex"],
                                wallet=self.wallet_name)
        signed = json.loads(signed_json)
        if not signed.get("complete"):
            raise RuntimeError(f"Signing incomplete: {signed}")
        txid = self._cli("sendrawtransaction", signed["hex"])
        self.mine(1)
        return txid

    def mine(self, blocks=1):
        """Mine blocks to confirm pending transactions."""
        mining_addr = self._cli("getnewaddress", wallet=self.wallet_name)
        self._cli("generatetoaddress", str(blocks), mining_addr,
                  wallet=self.wallet_name)


# ============================================================
# Connect-mode node (bridge to an EXISTING bitcoind)
# ============================================================

# Bitcoin Core's standard RPC ports per chain.
DEFAULT_RPC_PORTS = {"mainnet": 8332, "testnet4": 48332, "regtest": 18443}
# bitcoin-cli's -chain= values (client-side hint only -- see resolve_connect_node).
_CHAIN_CLI_FLAG = {"mainnet": "main", "testnet4": "testnet4", "regtest": "regtest"}
# getblockchaininfo's "chain" field -> our chain names. Signet is intentionally
# unsupported (not one of this app's three networks).
_CHAIN_REPORTED = {"main": "mainnet", "testnet4": "testnet4", "regtest": "regtest"}


def _default_bitcoin_datadir():
    """Standard per-platform Bitcoin Core datadir -- the real node's, used
    only to locate its .cookie file when --rpccookie isn't given."""
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Bitcoin")
    return os.path.expanduser("~/.bitcoin")


def _default_cookie_path(chain):
    base = _default_bitcoin_datadir()
    sub = {"mainnet": "", "testnet4": "testnet4", "regtest": "regtest"}[chain]
    return os.path.join(base, sub, ".cookie") if sub else os.path.join(base, ".cookie")


class ConnectNode:
    """Bridge to an EXISTING bitcoind the user already runs. Read-only
    wrapper around bitcoin-cli -- no spawn, no teardown, no datadir
    creation. Reuses the same _cli/_cli_json seam as RegtestNode so the
    request handlers and helpers below don't need to know which mode
    they're serving."""

    def __init__(self, host, port, chain, cookie_file=None, rpcuser=None, rpcpassword=None):
        self.host = host
        self.rpc_port = port
        self.chain = chain
        self.cookie_file = cookie_file
        self.rpcuser = rpcuser
        self.rpcpassword = rpcpassword

    def _cli(self, *args, timeout=30):
        cmd = [
            "bitcoin-cli",
            f"-chain={_CHAIN_CLI_FLAG[self.chain]}",
            f"-rpcconnect={self.host}",
            f"-rpcport={self.rpc_port}",
        ]
        if self.rpcuser is not None:
            cmd.append(f"-rpcuser={self.rpcuser}")
            cmd.append(f"-rpcpassword={self.rpcpassword}")
        else:
            cmd.append(f"-rpccookiefile={self.cookie_file}")
        cmd.extend(args)

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            raise RuntimeError(
                f"bitcoin-cli {' '.join(args)} timed out after {timeout}s"
            )

        stdout_str = stdout.decode("utf-8", errors="replace").strip()
        stderr_str = stderr.decode("utf-8", errors="replace").strip()

        if proc.returncode != 0:
            raise RuntimeError(
                f"bitcoin-cli {' '.join(args)} failed (rc={proc.returncode}): "
                f"{stderr_str}"
            )
        return stdout_str

    def _cli_json(self, *args, timeout=30):
        return json.loads(self._cli(*args, timeout=timeout))


def resolve_connect_node(connect_value, chain_arg, cookie_arg, rpcuser, rpcpassword):
    """Parse --connect's value and probe candidate chains (each with its own
    default port + cookie path, unless overridden) until one authenticates,
    confirming the reported chain via getblockchaininfo. bitcoin-cli's
    -chain= flag doesn't validate against the live daemon -- it only picks
    client-side defaults -- so it's safe to try one candidate at a time
    against the same host/port and trust getblockchaininfo's answer.
    """
    host = "127.0.0.1"
    port_override = None
    if connect_value:
        if ":" in connect_value:
            host, port_str = connect_value.rsplit(":", 1)
            port_override = int(port_str)
        else:
            host = connect_value

    candidates = [chain_arg] if chain_arg else ["mainnet", "testnet4", "regtest"]
    errors = []
    last_port = None
    for chain in candidates:
        port = port_override if port_override is not None else DEFAULT_RPC_PORTS[chain]
        last_port = port
        cookie_file = cookie_arg or _default_cookie_path(chain)
        node = ConnectNode(host, port, chain, cookie_file, rpcuser, rpcpassword)
        try:
            info = node._cli_json("getblockchaininfo", timeout=15)
        except Exception as e:
            errors.append(f"{chain} (port {port}): {e}")
            continue
        reported = info.get("chain")
        reported_norm = _CHAIN_REPORTED.get(reported)
        if reported_norm is None:
            errors.append(f"{chain} (port {port}): unsupported node chain '{reported}'")
            continue
        if chain_arg and reported_norm != chain_arg:
            raise RuntimeError(
                f"--chain {chain_arg} given, but the node at {host}:{port} "
                f"reports chain={reported}"
            )
        node.chain = reported_norm
        return node, info
    raise RuntimeError(
        f"Could not connect to bitcoind at {host}:{port_override or last_port}: "
        + "; ".join(errors)
    )


# ============================================================
# API helpers
# ============================================================

def _reshape_scantxoutset(result):
    """scantxoutset's 'unspents' -> esplora-shaped UTXO list."""
    utxos = []
    for u in result.get("unspents", []):
        utxos.append({
            "txid": u["txid"],
            "vout": u["vout"],
            "value": int(round(u["amount"] * 1e8)),
            "status": {"confirmed": True, "block_height": u.get("height", 0)},
        })
    return utxos


def _fetch_utxos_regtest(address):
    """Fetch UTXOs from the spawned regtest node using scantxoutset."""
    node = _regtest_node
    if not node:
        raise RuntimeError("No regtest node available")
    result = node._cli_json("scantxoutset", "start",
                            json.dumps([f"addr({address})"]))
    return _reshape_scantxoutset(result)


def _get_raw_tx_regtest(txid):
    """Get raw transaction hex from the spawned regtest node."""
    node = _regtest_node
    if not node:
        raise RuntimeError("No regtest node available")
    return node._cli("getrawtransaction", txid)


def _broadcast_regtest(raw_hex):
    """Broadcast raw transaction to the spawned regtest node + auto-mine."""
    node = _regtest_node
    if not node:
        raise RuntimeError("No regtest node available")
    txid = node._cli("sendrawtransaction", raw_hex)
    # Auto-mine so the tx is confirmed immediately. This is a spawn-mode-only
    # convenience -- --connect never mines on someone's real node.
    try:
        node.mine(1)
    except Exception:
        pass  # non-fatal
    return txid


# scantxoutset is synchronous and can take MINUTES against a mainnet node's
# full UTXO set (no address index). The handler's own subprocess timeout is
# set generously; the frontend's fetch timeout is raised to match in connect
# mode (see app.js).
CONNECT_SCAN_TIMEOUT = 600  # seconds

# Small per-address cache so the UI's repeated fetches (a retry, a reload)
# don't re-run a multi-minute scan for the same address within the window.
_UTXO_CACHE_TTL = 60  # seconds
_utxo_cache = {}  # address -> (fetched_at, utxos)
_utxo_cache_lock = threading.Lock()


def _fetch_utxos_connect(address):
    """Fetch UTXOs from the bridged node using scantxoutset, cached for
    _UTXO_CACHE_TTL seconds per address."""
    node = _connect_node
    if not node:
        raise RuntimeError("Not connected to a node")
    now = time.time()
    with _utxo_cache_lock:
        cached = _utxo_cache.get(address)
        if cached and now - cached[0] < _UTXO_CACHE_TTL:
            return cached[1]
    result = node._cli_json("scantxoutset", "start",
                            json.dumps([f"addr({address})"]),
                            timeout=CONNECT_SCAN_TIMEOUT)
    utxos = _reshape_scantxoutset(result)
    with _utxo_cache_lock:
        _utxo_cache[address] = (now, utxos)
    return utxos


def _get_raw_tx_connect(txid):
    """Get raw transaction hex from the bridged node. On mainnet/testnet4
    this needs the node's txindex=1 for an arbitrary (non-wallet,
    non-mempool) txid -- without it, bitcoin-cli's own error ("No such
    mempool or blockchain transaction...") is returned to the caller as-is,
    which is the same behavior _handle_raw_tx already gives regtest."""
    node = _connect_node
    if not node:
        raise RuntimeError("Not connected to a node")
    return node._cli("getrawtransaction", txid)


def _broadcast_connect(raw_hex):
    """Broadcast to the bridged node. No auto-mine -- that's a regtest-spawn
    convenience only; a bridged node's mempool/chain isn't this server's to
    manage."""
    node = _connect_node
    if not node:
        raise RuntimeError("Not connected to a node")
    return node._cli("sendrawtransaction", raw_hex, timeout=60)


def _estimate_fee_satvb(node, target):
    """estimatesmartfee's BTC/kB feerate -> ceil(sat/vB), floored at 1.
    Returns None if the node has no estimate yet or the RPC itself errors --
    the caller falls back to the flat 1 sat/vB default in that case."""
    try:
        result = node._cli_json("estimatesmartfee", str(target))
    except Exception:
        return None
    feerate = result.get("feerate")
    if not isinstance(feerate, (int, float)):
        return None
    sat_vb = feerate * 1e8 / 1000
    return max(1, math.ceil(sat_vb))


def _fees_connect(node):
    """Map estimatesmartfee at targets 1/3/6/144 onto mempool.space's preset
    shape. minimumFee reuses the 144-block (economy) estimate -- there's no
    fifth target given in the spec to derive it from separately. On regtest
    there's no real fee market (estimatesmartfee always errors), so this
    falls back to the same flat 1 sat/vB used by --regtest/static."""
    if node.chain == "regtest":
        return {"fastestFee": 1, "halfHourFee": 1, "hourFee": 1,
                "economyFee": 1, "minimumFee": 1}
    fastest = _estimate_fee_satvb(node, 1) or 1
    half_hour = _estimate_fee_satvb(node, 3) or 1
    hour = _estimate_fee_satvb(node, 6) or 1
    economy = _estimate_fee_satvb(node, 144) or 1
    return {
        "fastestFee": fastest, "halfHourFee": half_hour, "hourFee": hour,
        "economyFee": economy, "minimumFee": economy,
    }


# ============================================================
# HTTP Handler
# ============================================================

class PsbtServerHandler(SimpleHTTPRequestHandler):
    """Serves static files from project root + API endpoints for regtest/connect."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=_PROJECT_ROOT, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._handle_health()
        elif path == "/api/v1/fees/recommended":
            self._handle_fees()
        elif path == "/api/blocks/tip/height":
            self._handle_tip_height()
        elif re.match(r"^/api/address/.+/utxo$", path):
            address = path.split("/api/address/")[1].rsplit("/utxo", 1)[0]
            self._handle_utxos(address)
        elif re.match(r"^/api/tx/[a-fA-F0-9]{64}/hex$", path):
            txid = path.split("/api/tx/")[1].split("/hex")[0]
            self._handle_raw_tx(txid)
        else:
            # Serve static files
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b""
        body_str = body_bytes.decode("utf-8", errors="replace").strip()

        if path == "/api/tx":
            self._handle_broadcast(body_str)
        elif path == "/api/faucet":
            self._handle_faucet(json.loads(body_str) if body_str else {})
        elif path == "/api/mine":
            self._handle_mine(json.loads(body_str) if body_str else {})
        else:
            self._send_json({"error": "Not found"}, 404)

    # -- API handlers -----------------------------------------------

    def _handle_health(self):
        resp = {
            "status": "ok",
            "mode": _mode,
            # Back-compat: existing tests/tooling read this bool.
            "regtest": _mode == "regtest",
        }
        if _mode == "regtest":
            resp["chain"] = "regtest"
            resp["rpc_port"] = _regtest_node.rpc_port
            resp["datadir"] = _regtest_node.datadir
        elif _mode == "connect":
            resp["chain"] = _connect_node.chain
            resp["rpc_host"] = _connect_node.host
            resp["rpc_port"] = _connect_node.rpc_port
        else:
            resp["chain"] = None
        self._send_json(resp)

    def _handle_fees(self):
        if _mode == "connect":
            try:
                self._send_json(_fees_connect(_connect_node))
            except Exception:
                self._send_json({
                    "fastestFee": 1, "halfHourFee": 1, "hourFee": 1,
                    "economyFee": 1, "minimumFee": 1,
                })
            return
        self._send_json({
            "fastestFee": 1, "halfHourFee": 1, "hourFee": 1,
            "economyFee": 1, "minimumFee": 1,
        })

    def _handle_tip_height(self):
        """mempool.space-compatible: plain-text integer."""
        node = _regtest_node if _mode == "regtest" else _connect_node if _mode == "connect" else None
        if not node:
            self._send_text("Server not connected to a node", 503)
            return
        try:
            self._send_text(node._cli("getblockcount"))
        except Exception as e:
            self._send_text(str(e), 500)

    def _handle_utxos(self, address):
        if _mode == "regtest":
            fetcher = _fetch_utxos_regtest
        elif _mode == "connect":
            fetcher = _fetch_utxos_connect
        else:
            self._send_json({"error": "Server not connected to a node"}, 503)
            return
        try:
            utxos = fetcher(address)
            self._send_json(utxos)
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_raw_tx(self, txid):
        if _mode == "regtest":
            fetcher = _get_raw_tx_regtest
        elif _mode == "connect":
            fetcher = _get_raw_tx_connect
        else:
            self._send_text("Server not connected to a node", 503)
            return
        try:
            raw_hex = fetcher(txid)
            self._send_text(raw_hex)
        except Exception as e:
            self._send_text(str(e), 404)

    def _handle_broadcast(self, raw_hex):
        if _mode == "regtest":
            broadcaster = _broadcast_regtest
        elif _mode == "connect":
            broadcaster = _broadcast_connect
        else:
            self._send_text("Server not connected to a node", 503)
            return
        if not raw_hex:
            self._send_text("Empty transaction hex", 400)
            return
        try:
            txid = broadcaster(raw_hex)
            self._send_text(txid)
        except Exception as e:
            self._send_text(str(e), 400)

    def _handle_faucet(self, params):
        if _mode != "regtest":
            self._send_json({"error": "Faucet requires --regtest mode"}, 400)
            return
        address = params.get("address")
        amount = params.get("amount", "1.0")
        if not address:
            self._send_json({"error": "Missing address"}, 400)
            return
        try:
            amount_str = str(float(amount))
            txid = _regtest_node.fund_address(address, amount_str)
            self._send_json({
                "success": True,
                "txid": txid,
                "address": address,
                "amount_btc": amount_str,
                "amount_sat": int(float(amount_str) * 1e8),
            })
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    def _handle_mine(self, params):
        if _mode != "regtest":
            self._send_json({"error": "Mining requires --regtest mode"}, 400)
            return
        blocks = int(params.get("blocks", 1))
        if blocks < 1 or blocks > 100:
            self._send_json({"error": "blocks must be 1-100"}, 400)
            return
        try:
            _regtest_node.mine(blocks)
            self._send_json({"success": True, "blocks_mined": blocks})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # -- Response helpers -------------------------------------------

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text, status=200):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        sys.stderr.write(f"[Server] {args[0]}\n")


class ReusableTCPServer(HTTPServer):
    allow_reuse_address = True
    allow_reuse_port = True

    def handle_error(self, request, client_address):
        # A client dropping a connection mid-transfer is routine; the default
        # handler prints a full traceback, which trips run_all.py's abort scan.
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)

    def process_request(self, request, client_address):
        """Handle each request in a new thread to prevent single-threaded
        blocking -- important in --connect mode, where a scantxoutset call
        can run for minutes."""
        t = threading.Thread(target=self.process_request_thread,
                             args=(request, client_address), daemon=True)
        t.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


# ============================================================
# Main
# ============================================================

def run_server(port=8000, regtest=False, connect_value=None, chain=None,
               rpccookie=None, rpcuser=None, rpcpassword=None):
    """Start the HTTP server, optionally spawning a regtest node (--regtest)
    or bridging an existing one (--connect)."""
    global _regtest_node, _connect_node, _mode

    if regtest:
        for binary in ["bitcoind", "bitcoin-cli"]:
            if shutil.which(binary) is None:
                print(f"ERROR: '{binary}' not found in PATH.")
                print("Install Bitcoin Core: brew install bitcoin (macOS)")
                sys.exit(1)

        print("=" * 60)
        print("Starting Bitcoin Core regtest node...")
        print("=" * 60)
        _regtest_node = RegtestNode()
        _regtest_node.start()
        _mode = "regtest"
        print()
    elif connect_value is not None:
        if shutil.which("bitcoin-cli") is None:
            print("ERROR: 'bitcoin-cli' not found in PATH.")
            print("Install Bitcoin Core: brew install bitcoin (macOS)")
            sys.exit(1)

        print("=" * 60)
        print("Connecting to existing bitcoind...")
        print("=" * 60)
        try:
            _connect_node, info = resolve_connect_node(
                connect_value, chain, rpccookie, rpcuser, rpcpassword)
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)
        _mode = "connect"
        print(f"  Connected: chain={_connect_node.chain} "
              f"host={_connect_node.host} port={_connect_node.rpc_port} "
              f"blocks={info.get('blocks')}")
        print()

    server = ReusableTCPServer(("0.0.0.0", port), PsbtServerHandler)
    print(f"Dustpan Server running on http://localhost:{port}")
    if _mode == "regtest":
        print("  Mode: REGTEST (test coins, no real value)")
    elif _mode == "connect":
        print(f"  Mode: CONNECT (bridging {_connect_node.chain} via "
              f"{_connect_node.host}:{_connect_node.rpc_port} -- no funds "
              "spawned or mined here)")
        print("  Note: /address/:addr/utxo uses scantxoutset -- the first")
        print("  lookup for a given address can take MINUTES on mainnet.")
        print("  Note: Tor Browser on Tails cannot reach localhost -- this")
        print("  bridge is for a normal desktop browser only.")
    print("\nPress Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()
        if _regtest_node:
            _regtest_node.stop()
            _regtest_node = None
        _connect_node = None
        print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dustpan local dev server / node bridge.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("port", nargs="?", type=int, default=8000,
                        help="HTTP port to serve on (default: 8000)")
    parser.add_argument("--regtest", action="store_true",
                        help="spawn a throwaway regtest bitcoind (faucet + auto-mine)")
    parser.add_argument("--connect", nargs="?", const="", default=None,
                        metavar="HOST[:PORT]",
                        help="bridge an EXISTING bitcoind instead of spawning one "
                             "(default host 127.0.0.1, default rpcport by chain)")
    parser.add_argument("--chain", choices=["mainnet", "testnet4", "regtest"],
                        default=None,
                        help="--connect only; default: auto-detect via getblockchaininfo")
    parser.add_argument("--rpccookie", default=None, metavar="FILE",
                        help="--connect only; default: the chain's standard cookie "
                             "path (macOS: ~/Library/Application Support/Bitcoin, "
                             "Linux: ~/.bitcoin; regtest/testnet4 subdirs)")
    parser.add_argument("--rpcuser", default=None, help="--connect only")
    parser.add_argument("--rpcpassword", default=None, help="--connect only")
    args = parser.parse_args()

    if args.regtest and args.connect is not None:
        parser.error("--regtest and --connect are mutually exclusive")
    if args.connect is None and (args.chain or args.rpccookie or args.rpcuser or args.rpcpassword):
        parser.error("--chain/--rpccookie/--rpcuser/--rpcpassword require --connect")
    if bool(args.rpcuser) != bool(args.rpcpassword):
        parser.error("--rpcuser and --rpcpassword must be given together")

    run_server(args.port, regtest=args.regtest, connect_value=args.connect,
              chain=args.chain, rpccookie=args.rpccookie,
              rpcuser=args.rpcuser, rpcpassword=args.rpcpassword)
