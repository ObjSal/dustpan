"""
Coldcard access for the test suites: prefer the headless simulator, fall
back to a physical device.

The simulator is the Coldcard firmware's own desktop build
(https://github.com/Coldcard/firmware, unix/headless.py). It speaks the
full ckcc USB protocol over /tmp/ckcc-simulator.sock, so `ckcc -x` drives
it exactly like a device -- plus two extras a real device refuses:

  - EXEC <python>  runs code inside the firmware (used to switch chains:
                   XRT for regtest, XTN for testnet4)
  - sim_keypress   injects key presses (used to approve transactions
                   without a human)

Selection:
  - COLDCARD_PHYSICAL=1        -> always use the real device (ckcc, no -x)
  - otherwise                  -> simulator if its socket is live or it can
                                  be launched from COLDCARD_FIRMWARE
  - COLDCARD_FIRMWARE          -> firmware checkout (default
                                  ~/Projects/coldcard-firmware)
"""
import os
import subprocess
import threading
import time

SIM_SOCKET = "/tmp/ckcc-simulator.sock"
FIRMWARE_DIR = os.environ.get(
    "COLDCARD_FIRMWARE", os.path.expanduser("~/Projects/coldcard-firmware"))

_started_proc = None


def physical_forced():
    return os.environ.get("COLDCARD_PHYSICAL") == "1"


def simulator_possible():
    if physical_forced():
        return False
    return os.path.exists(SIM_SOCKET) or \
        os.path.isfile(os.path.join(FIRMWARE_DIR, "unix", "headless.py"))


def using_simulator():
    return not physical_forced() and os.path.exists(SIM_SOCKET)


def ckcc(*args):
    """argv for a ckcc invocation against the selected Coldcard."""
    base = ["ckcc", "-x"] if using_simulator() else ["ckcc"]
    return base + [str(a) for a in args]


def _device():
    from ckcc.client import ColdcardDevice
    return ColdcardDevice(sn=SIM_SOCKET)


def set_chain(chain):
    """XRT (regtest), XTN (testnet), BTC (mainnet). Simulator only --
    a physical device changes chain in its settings menu."""
    if not using_simulator():
        return False
    dev = _device()
    r = dev.send_recv(
        b'EXEC' + f'from glob import settings; settings.set("chain", "{chain}"); RV.write("ok")'.encode(),
        timeout=10000, encrypt=False)
    dev.close()
    if r != b'ok':
        raise RuntimeError(f"simulator chain switch failed: {r!r}")
    return True


def start_simulator(chain=None):
    """Ensure a simulator is reachable; launch headless.py if needed.
    Returns True when the simulator is in use (chain applied), False when
    the physical device should be used instead."""
    global _started_proc
    if physical_forced():
        return False
    if not os.path.exists(SIM_SOCKET):
        unix_dir = os.path.join(FIRMWARE_DIR, "unix")
        if not os.path.isfile(os.path.join(unix_dir, "headless.py")):
            return False
        print(f"  Starting Coldcard simulator (headless) from {unix_dir}...")
        _started_proc = subprocess.Popen(
            ["python3", "headless.py"], cwd=unix_dir,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        # Never leak the simulator past the test run that launched it (a
        # pre-existing one is left alone: _started_proc stays None for it).
        import atexit
        atexit.register(stop_simulator)
        for _ in range(60):
            if os.path.exists(SIM_SOCKET):
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("simulator socket never appeared")
        time.sleep(2)  # let USB task come up
    if chain:
        set_chain(chain)
    return True


def stop_simulator():
    """Stop the simulator ONLY if this run launched it. headless.py runs the
    firmware (coldcard-mpy) as a child in the same new session, so kill the
    whole process group -- terminating just headless.py orphans the firmware
    and leaks the socket."""
    global _started_proc
    if _started_proc is not None:
        import signal
        try:
            os.killpg(os.getpgid(_started_proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            _started_proc.terminate()
        try:
            _started_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(_started_proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                _started_proc.kill()
        _started_proc = None
        try:
            os.unlink(SIM_SOCKET)
        except OSError:
            pass


class Approver:
    """Presses 'y' on the simulator while a `ckcc sign` waits for approval.
    Waits a beat for the upload to finish and the approval story to be on
    screen, then keeps confirming until stopped. No-op on a real device,
    where the human approves."""

    def __init__(self, initial_delay=3.0, interval=1.0):
        self.initial_delay = initial_delay
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if not using_simulator():
            return self
        from ckcc.protocol import CCProtocolPacker

        def run():
            if self._stop.wait(self.initial_delay):
                return
            dev = _device()
            try:
                while not self._stop.is_set():
                    try:
                        dev.send_recv(CCProtocolPacker.sim_keypress(b'y'), timeout=3000)
                    except Exception:
                        pass
                    self._stop.wait(self.interval)
            finally:
                dev.close()

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        return False


def ensure_testnet4_funds(cc_addr, wif_key, wif_address, mempool_api,
                          fund_sats=9000, fee_sats=400, timeout=120):
    """The simulator's fixed seed starts with an empty testnet4 wallet.
    When cc_addr has no UTXOs, fund it from the test WIF (change back to the
    WIF address) and wait for the funding tx to reach the mempool. Returns
    True when cc_addr has at least one UTXO afterwards."""
    import json
    from urllib.request import urlopen, Request
    from embit import ec as embit_ec
    from embit.psbt import PSBT
    from embit.transaction import Transaction, TransactionInput, TransactionOutput
    from embit.script import Script
    from embit.finalizer import finalize_psbt

    def utxos(addr):
        with urlopen(f"{mempool_api}/address/{addr}/utxo", timeout=30) as r:
            return json.loads(r.read())

    if utxos(cc_addr):
        return True
    print(f"  CC address has no testnet4 UTXOs; funding {fund_sats} sats from the WIF...")
    wif_privkey = embit_ec.PrivateKey.from_wif(wif_key)
    wus = sorted(utxos(wif_address), key=lambda u: -u["value"])
    if not wus:
        return False
    picked, total = [], 0
    for u in wus:
        picked.append(u); total += u["value"]
        if total >= fund_sats + fee_sats + 600:
            break
    change = total - fund_sats - fee_sats
    if change <= 546:
        return False
    tx = Transaction(version=2,
        vin=[TransactionInput(txid=bytes.fromhex(u["txid"]), vout=u["vout"],
                              sequence=0xfffffffd) for u in picked],
        vout=[TransactionOutput(value=fund_sats, script_pubkey=Script.from_address(cc_addr)),
              TransactionOutput(value=change, script_pubkey=Script.from_address(wif_address))],
        locktime=0)
    psbt = PSBT(tx)
    for i, u in enumerate(picked):
        with urlopen(f"{mempool_api}/tx/{u['txid']}/hex", timeout=30) as r:
            prev = Transaction.from_string(r.read().decode())
        psbt.inputs[i].witness_utxo = prev.vout[u["vout"]]
    assert psbt.sign_with(wif_privkey) == len(picked)
    raw = finalize_psbt(psbt).serialize().hex()
    req = Request(f"{mempool_api}/tx", data=raw.encode(),
                  headers={"Content-Type": "text/plain"})
    with urlopen(req, timeout=30) as r:
        txid = r.read().decode().strip()
    print(f"  Funding tx broadcast: {txid[:16]}...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if utxos(cc_addr):
            return True
        time.sleep(5)
    return False


def sign_psbt(psbt_in_path, psbt_out_path, timeout=300):
    """Sign a PSBT with the selected Coldcard; returns an object with
    returncode / stdout / stderr like subprocess.run.

    Simulator: done in-process over ONE socket connection -- upload, start
    signing, then alternate sim_keypress('y') (to approve whatever story is
    on screen) with get_signed_txn polling. Running `ckcc sign` as a
    subprocess while another connection injects keypresses interleaves USB
    frames on the shared unix socket (FramingError on the firmware,
    "Unknown response signature" on the client), so everything must go
    through the same connection.

    Physical device: plain `ckcc sign`; the human approves.
    """
    from types import SimpleNamespace
    if not using_simulator():
        return subprocess.run(ckcc("sign", psbt_in_path, psbt_out_path),
                              capture_output=True, text=True, timeout=timeout)
    from ckcc.cli import real_file_upload
    from ckcc.protocol import CCProtocolPacker
    dev = _device()
    try:
        with open(psbt_in_path, 'rb') as fd:
            txn_len, sha = real_file_upload(fd, dev)
        ok = dev.send_recv(CCProtocolPacker.sign_transaction(txn_len, sha, flags=0), timeout=None)
        assert ok is None, f"sign_transaction: {ok!r}"
        deadline = time.time() + timeout
        done = None
        while time.time() < deadline:
            time.sleep(0.5)
            # Approve whatever story is up, then ask for the result. Both on
            # this one connection, so the exchanges serialize.
            try:
                dev.send_recv(CCProtocolPacker.sim_keypress(b'y'), timeout=5000)
            except Exception:
                pass
            done = dev.send_recv(CCProtocolPacker.get_signed_txn(), timeout=None)
            if done is not None:
                break
        if done is None:
            return SimpleNamespace(returncode=1, stdout='', stderr='timed out waiting for signed result')
        if not isinstance(done, tuple) or len(done) != 2:
            return SimpleNamespace(returncode=1, stdout='', stderr=f'signing failed: {done!r}')
        result_len, result_sha = done
        result = dev.download_file(result_len, result_sha, file_number=1)
        with open(psbt_out_path, 'wb') as f:
            f.write(result)
        return SimpleNamespace(returncode=0, stdout=f'{result_len} bytes', stderr='')
    except Exception as e:
        return SimpleNamespace(returncode=1, stdout='', stderr=f'{type(e).__name__}: {e}')
    finally:
        dev.close()
