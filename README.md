# 🧹 Dustpan

*Formerly Bitcoin Address Sweeper.*

Dustpan — sweep Bitcoin from addresses, hardware wallets, and paper wallets into a single transaction (PSBT). Built on PSBTs ([BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)).

**[Live Demo](https://objsal.github.io/join-psbts/)**

## What It Does

This tool lets multiple wallet holders collaborate on a single Bitcoin transaction. Each person contributes UTXOs as inputs, signs their portion independently, and the results are combined into a finalized transaction ready for broadcast.

### Workflow

1. **Create** -- Add inputs (UTXOs) from multiple wallets by address, xpub (HD wallet import dialog), or WIF, set outputs and fee, then download the unsigned PSBT or display it as a QR code
2. **Sign** -- Each wallet holder signs the PSBT with their own wallet (hardware wallet, Bitcoin Core, hot wallet, or paper wallet)
3. **Combine & Finalize** -- Upload all signed PSBTs, the tool merges signatures and produces the raw transaction
4. **Broadcast** -- Send the finalized transaction to the Bitcoin network via mempool.space

### Signing Approaches

| Approach | How it works | Upload |
|----------|-------------|--------|
| **Parallel** | Each party independently signs a copy of the unsigned PSBT | Upload all signed copies |
| **Serial** | Party A signs, passes to B, B signs, passes to C... | Upload the single final file |

Both approaches work through the same Combine & Finalize step.

## Features

- **Fetch UTXOs** by address, extended public key (xpub/zpub/vpub/tpub/ypub/upub), or WIF private key from mempool.space (or local regtest server) -- pasting an extended key opens an **Import HD Wallet** dialog that derives receive/change addresses locally (free, unlimited paging) and fetches UTXOs for exactly the addresses you tick; WIF input derives both P2WPKH and P2TR addresses and fetches UTXOs from both
- **Inline signing** for hot/paper wallets -- when all UTXOs have WIF private keys, signs and finalizes the transaction in-browser without needing external signing tools, going straight from Create to Broadcast
- **Fee rate presets** pulled live from the network (fast/medium/slow), with estimated fee and available sats display
- **Transaction preview** on both steps -- verdict, stats, and money-flow diagram rendered by a sandboxed [PSBT Decoder](https://github.com/ObjSal/psbt-decoder) iframe, with a link to the full decoder
- **Anti-fee-sniping lock time** (None / Block / Date presets) defaulting to the current block height, matching Bitcoin Core, Electrum, and Sparrow
- **Key-origin enforcement** -- every input must carry either its WIF or a complete key origin (fingerprint + path + pubkey, supplied automatically by xpub fetches), plus guards that catch the Coldcard Q legacy-scriptSig finalize bug before broadcast
- **Optional tip** with preset percentages (0.99%, 0.5%, 0.1%) and per-network donation addresses -- included as a PSBT output only when sats > 0
- **Output percentage labels** showing each output's share of total input, with a Wipe option to sweep remaining balance
- **QR code display** using [BBQr](https://bbqr.org/) protocol for air-gapped signing with hardware wallets like Coldcard Q (auto-splits large PSBTs into animated multi-part QR sequences)
- **QR code scanning** to upload signed PSBTs from hardware wallets via camera, with BBQr multi-part support and progress bar -- combine QR-scanned and file-uploaded PSBTs from different sources
- **Camera scanning on the Create step** -- scan an address, WIF, xpub, BIP21 URI, or paper-wallet sweep URL straight into the fetch box
- **Hardware wallet support** with BIP32 derivation paths, master fingerprint input (per xpub source, auto-propagated to all UTXOs), and xpub auto-derivation of compressed public keys (supports xpub/ypub/zpub/vpub/tpub/upub formats via SLIP-132 normalization)
- **CLI signing tool** (`tools/sign-psbt.py`) for hot wallet signing with WIF keys
- **Network auto-selection** -- Mainnet on GitHub Pages, Testnet4 on local static server, Regtest with regtest server
- **Network support** for Mainnet, Testnet4, and Regtest
- **Custom backend** -- point any network at your own esplora-compatible server (electrs, a self-hosted mempool instance, Blockstream esplora) instead of mempool.space, so addresses never leave your network (see [Use your own node](#use-your-own-node) above); restricted to same-origin/mempool.space/localhost by the page's CSP, hidden in the offline build
- **Step indicator wizard** with two steps (Create → Broadcast) -- the Broadcast step adapts to the inputs: all-WIF sweeps sign inline and go straight to broadcast, hardware-wallet flows show upload/combine first
- **Guided workflow** with brief instructions under each step
- **No server required** -- runs entirely in the browser on GitHub Pages
- **Offline build for Tails** -- `tools/build-offline.py` produces one self-contained `dustpan-offline.html` for `file://` use with no server and no network calls (see [Offline build (Tails)](#offline-build-tails) below)
- **Regtest mode** with a local Python server for development and testing
- **Connect-bridge mode** -- point `server/server.py --connect` at a bitcoind you already run (any chain) with no address index required, so node-runners without electrs can still fetch UTXOs, fees, and broadcast without leaving their own node (see [Bridge a bare bitcoind](#bridge-a-bare-bitcoind) above)

## Usage

### GitHub Pages (Mainnet / Testnet)

Visit the [live demo](https://objsal.github.io/join-psbts/) -- no installation needed.

### Local Development (Regtest)

Requires [Bitcoin Core](https://bitcoincore.org/en/download/) (bitcoind + bitcoin-cli).

```bash
# Start the regtest server (launches bitcoind, mines initial blocks)
python3 server/server.py 8000 --regtest

# Open in browser
open http://localhost:8000/index.html
```

The server provides a faucet and auto-mining, and exposes mempool.space-compatible API endpoints so the frontend works identically across all networks.

### Offline build (Tails)

Tor Browser on [Tails](https://tails.net/) can't reach `localhost` (no dev server) and can't install a PWA, so the offline deliverable is **one self-contained HTML file** opened straight from disk (`file://`) -- no server, no install. UTXOs and PSBTs move by manual entry, file upload, or QR code only; everything that needs a network call (fetching UTXOs by address/xpub, fee-rate/tip-height lookups, broadcasting) is disabled or replaced with a manual hand-off.

**Download it (recommended):** every tagged release on the [Releases page](https://github.com/ObjSal/dustpan/releases) ships `dustpan-offline.html` with a `.sha256` checksum and a GPG detached signature (`.asc`) -- grab the latest, then jump to *Verify before trusting it* below. Building it yourself from a reviewed checkout is the more paranoid alternative:

**Build it:**

```bash
python3 tools/build-offline.py            # writes dist/dustpan-offline.html
python3 tools/build-offline.py --release  # + dist/dustpan-offline.html.sha256,
                                           #   and prints (does not run) the
                                           #   gpg detached-sign command
```

Requires the `psbt-decoder` submodule to be checked out (`git submodule update --init`) -- it's composed into the offline file's Transaction Preview at build time, never modified.

**Verify before trusting it:**

```bash
cd dist
shasum -a 256 -c dustpan-offline.html.sha256   # integrity
gpg --verify dustpan-offline.html.asc dustpan-offline.html  # authenticity, if you signed a release
```

**Get it onto Tails:** copy `dustpan-offline.html` (and its `.sha256`/`.asc` if you built `--release`) to a USB drive, then copy it from the USB drive into your Tails **Home** or **Persistent Storage** folder -- Tor Browser's sandbox can't read arbitrary USB mount paths directly. Open it with `File → Open File...` (a `file://` URL). Tor Browser's **Security Level** must be **Standard** or **Safer** -- **Safest disables JavaScript**, and this is a JavaScript wallet, so it can't run at all under Safest.

**What's different offline:** an **OFFLINE** badge appears next to the title; the network defaults to Mainnet with no server probe; the "Fetch Unspent" row is replaced with a hint to add inputs manually (`+ Add Input`: txid/vout/value/scriptPubKey) or build the PSBT elsewhere and sign it here; the fee rate is manual-only (defaults to 1 sat/vB); lock time still defaults to Block mode but you type the current height yourself (no tip-height fetch); and the Broadcast step drops the mempool.space POST for a QR code of the raw transaction (BBQr, same pipeline as PSBT display) plus the existing Download button, so you can move the finished transaction to any online device to actually broadcast it. Manual UTXO/output entry, WIF signing, and PSBT upload/scan/combine all keep working exactly as online -- they never needed a network. The offline file also carries a stricter Content-Security-Policy than the online page (`connect-src 'none'`) -- see "Content Security Policy" below -- so nothing in it can make a network connection even if something tried. See `CLAUDE.md`'s "Offline build (Tails)" architecture notes for the guard-by-guard breakdown.

#### Example 1 -- sweep a paper wallet, fully air-gapped (the WIF never touches an online machine)

On any **online** device (phone is fine), using a block explorer or your own node, write down for each UTXO you're sweeping:

- `txid` and `vout` (output index)
- value in **sats**
- the address's `scriptPubKey` hex (explorers show it on the transaction's output; for a native-SegWit `bc1q...` address it looks like `0014<20-byte-hash>`)
- the current **block height** and a reasonable **fee rate** (sat/vB)

On **Tails**, open `dustpan-offline.html`:

1. `+ Add Input` -- paste txid / vout / value / scriptPubKey; expand the input's **WIF** field and paste the private key (a ✔️ appears on the toggle when it parses).
2. Repeat for each UTXO. Add your destination address as an output and tick **Wipe** to sweep everything after fees (or enter amounts manually).
3. Set the **Fee Rate** you noted; under **Lock Time**, type the block height you noted (or choose *None*).
4. When every input has a WIF, the button reads **Create, Sign & Finalize** -- click it. You land on the Broadcast step with the finished transaction as a QR code and a **Download Transaction** (`.txn`) button. Check the Transaction Preview before moving on.
5. Broadcast from any online device: scan the QR (or carry the `.txn` file out on the USB stick) and paste the hex into mempool.space's *Broadcast Transaction* page, or run `bitcoin-cli sendrawtransaction <hex>` on your node. The private key stayed on Tails the whole time.

#### Example 2 -- build the PSBT on Tails, sign it with another wallet

Use this when the keys live in a hardware or software wallet rather than on paper. Because there's no network, you type the UTXO details exactly as in Example 1, but leave the WIF field empty:

1. Add the inputs manually (txid / vout / value / scriptPubKey). For a signer that matches inputs by key origin (e.g. a hardware wallet), also fill the input's fingerprint / derivation path / pubkey fields; for a signer that matches by address (Bitcoin Core's `walletprocesspsbt`, Sparrow or Electrum with the keys loaded), tick the **"Inputs with no private key and no key origin will be signed by a software wallet..."** checkbox instead.
2. Add outputs, fee rate, and lock time as above, then click **Create PSBT**. Show the PSBT as an animated QR (**Show QR Code**) or download the `.psbt` file to the USB stick.
3. Sign it in the other wallet (e.g. a Coldcard Q scans the QR directly; Sparrow opens the file). Bring the signed PSBT back the same way -- the Broadcast step's upload section accepts files and scans QR codes, including multi-part BBQr.
4. Click **Combine & Finalize**, verify the Transaction Preview, and hand the finished transaction out via QR or `.txn` exactly as in Example 1. Mixed sweeps work too: rows that *do* have a WIF are signed in the page automatically at the combine step.

**Tip for both flows:** double-check the scriptPubKey you typed -- an input whose script doesn't match its address simply can't be signed, and offline there's no fetch step to catch the typo for you. The Transaction Preview on both steps shows amounts, addresses, and the fee before anything leaves the page.

### Use your own node

Privacy-conscious users can point the app at their own esplora-compatible backend instead of mempool.space, so their addresses never leave their network. Any of these work: [electrs](https://github.com/romanz/electrs), a self-hosted [mempool](https://github.com/mempool/mempool) instance backed by [Fulcrum](https://github.com/cculianu/Fulcrum), or [Blockstream's esplora](https://github.com/Blockstream/electrs) itself.

Open the **Backend** collapsible near the network dropdown, paste your server's base URL (e.g. `http://127.0.0.1:3006/api`), and click **Apply** -- it probes `/blocks/tip/height` and, if reachable, saves the override for the *currently selected network* in `localStorage` (so a regtest override never leaks onto mainnet or vice versa). **Reset** clears it and falls back to mempool.space.

**Only three kinds of origin are accepted:** the page's own origin, `https://mempool.space` (any path), and `localhost`/`127.0.0.1` on any port over http or https. This isn't a UI-only restriction -- it mirrors index.html's `connect-src` Content-Security-Policy directive exactly, so even a compromised or buggy page could never phone home to a third-party host with an address or key. Typing `http://umbrel.local:3006` or any other LAN hostname is rejected with an explanation, because the CSP would silently block the request anyway (a meta CSP can't be loosened at runtime). To reach a node that isn't already on localhost:

- **Tunnel it over SSH** (the easy path, and the one that keeps the CSP as strict as it already is): `ssh -L 3006:umbrel.local:3006 user@yournode`, then point the Backend field at `http://127.0.0.1:3006`.
- **Self-host these static files** on the same origin as your backend -- same-origin is always allowed, and this is how a fully self-hosted deployment (frontend + electrs behind one reverse proxy) works.

Every other endpoint (`/address/:addr/utxo`, `/tx/:txid/hex`, `POST /tx`, `/blocks/tip/height`) is stock esplora already, so a plain electrs or esplora instance needs no adapter. Fee-rate estimation additionally falls back automatically: the app tries mempool.space's richer `/v1/fees/recommended` first, and if that 404s (a stock esplora backend doesn't serve it) falls back to esplora's plain `/fee-estimates` map (confirmation-target -> sat/vB), synthesizing the same Fast/Med/Slow preset shape from it. If neither endpoint answers, fee entry falls back to manual, same as it always has.

**Tails / offline build:** this feature only makes sense for the **online** build on a normal desktop browser. Tor Browser on Tails can't reach `localhost` at all, and the offline build's CSP is `connect-src 'none'` -- no network request can succeed from it, custom backend or otherwise -- so the whole Backend section is hidden there.

### Bridge a bare bitcoind

Already run `bitcoind` but don't have an address index (electrs/Fulcrum) in front of it? `server/server.py` can bridge it directly -- no address index needed, at the cost of slow, history-less UTXO lookups (see below). If you *do* have electrs or a similar esplora-compatible index running, use [Custom backend](#use-your-own-node) instead -- it's instant and this bridge has no reason to exist for you.

```bash
# Cookie-file auth (default: bitcoind's own datadir for the detected chain --
# macOS ~/Library/Application Support/Bitcoin, Linux ~/.bitcoin; regtest/
# testnet4 subdirs). Chain is auto-detected via getblockchaininfo.
python3 server/server.py 8000 --connect

# A remote or non-default node, and/or explicit rpcuser/rpcpassword auth
python3 server/server.py 8000 --connect 192.168.1.50:8332 \
  --rpcuser youruser --rpcpassword yourpassword

# Explicit cookie file and chain (skips the chain-detection probe)
python3 server/server.py 8000 --connect --chain testnet4 \
  --rpccookie ~/.bitcoin/testnet4/.cookie
```

Then open `http://localhost:8000/index.html` -- the frontend detects the bridge via `/api/health` (`mode: "connect"`) and auto-selects the bridged chain's network, same as `--regtest` auto-selects regtest.

**How it differs from `--regtest`:** nothing is spawned, owned, faucet-funded, or auto-mined -- this mode only ever runs read-only-ish RPCs (`getblockchaininfo`, `getblockcount`, `getrawtransaction`, `estimatesmartfee`, `scantxoutset`) plus `sendrawtransaction` for the one broadcast you ask for. `/api/faucet` and `/api/mine` are refused with a clear error, exactly as they are on a plain static server.

**UTXO lookups are slow -- read this before pointing it at mainnet.** Without an address index, `/address/:addr/utxo` runs `scantxoutset`, which walks the **entire UTXO set** on every call. On regtest/testnet4 this is fast; on mainnet the *first* lookup for an address can take several **minutes**. The frontend raises its fetch timeout to 10 minutes in this mode and shows a "scanning the node's UTXO set" status line while it waits, and the bridge caches each address's result for 60 seconds so retries and page reloads don't repeat the scan. There's no history either -- `scantxoutset` only sees the current UTXO set, so already-spent outputs never show up (irrelevant for sweeping, since you only care about what's spendable now).

**mainnet/testnet4 `/tx/:txid/hex` needs `txindex=1`.** Without it, `getrawtransaction` only finds your own wallet's transactions and anything currently in the mempool -- an arbitrary confirmed txid from someone else's transaction will 404. `nonWitnessUtxo` lookups for non-segwit inputs need this; native segwit and taproot inputs don't need it.

**Tails / offline build:** same as [Custom backend](#use-your-own-node) -- this is a normal-desktop-browser feature. Tor Browser on Tails cannot reach `localhost` at all, so `--connect` (like `--regtest`) is never reachable from a Tails session; use the [offline build](#offline-build-tails) there instead.

## Testing

```bash
# Preferred: run every local suite in the right order with per-suite logs
python3 tests/run_all.py             # everything that runs locally
python3 tests/run_all.py --testnet4  # + the two real-testnet4 Coldcard suites
python3 tests/run_all.py --list      # show the plan / skip reasons

# Unit tests -- index.html, 443 tests, no bitcoind needed (~45s)
# Includes building and driving the offline (Tails) single-file build via file://
python3 tests/test_psbt_builder.py

# Byte-for-byte comparison against Bitcoin Core -- 85 tests
# Asserts the unsigned tx is identical to createrawtransaction output;
# needs an existing regtest node (CN_NODE_HOST/CN_NODE_PORT + RPC credentials via env)
python3 tests/test_core_tx_comparison.py

# E2E regtest tests -- 148 tests, requires bitcoind + bitcoin-cli (~120s)
# Covers P2WPKH + P2TR (Taproot), parallel + serial signing,
# WIF fetch + inline signing, and mixed WIF partial signing
python3 tests/test_regtest_e2e.py

# Connect-bridge tests -- 38 tests, requires bitcoind + bitcoin-cli (~30s)
# Bridges a regtest node server.py did NOT spawn (server/server.py --connect);
# health/tip/UTXO/fee/broadcast endpoints, cache TTL, faucet/mine refusal,
# and one browser pass proving network auto-select + UI fetch through it
python3 tests/test_connect_mode.py

# Coldcard simulation tests -- 43 tests, requires bitcoind + embit (~120s)
# Simulates Coldcard signing via bitcoin-cli walletprocesspsbt
python3 tests/test_coldcard_simulation.py

# Coldcard regtest tests -- 29 tests, requires ckcc + bitcoind + embit
# Uses the Coldcard firmware's headless simulator; COLDCARD_PHYSICAL=1 for a real MK4
python3 tests/_test_coldcard_regtest.py

# Coldcard testnet4 tests -- 26 tests, requires ckcc + embit (simulator or real MK4)
# Builds mixed WIF+CC PSBT, signs via ckcc, broadcasts to testnet4
python3 tests/_test_coldcard_testnet4.py

# Website + Coldcard E2E tests -- 25 tests, requires ckcc + Playwright
# Full browser flow: fetch UTXOs, set HW info, create/sign/combine/broadcast
python3 tests/_test_coldcard_website_e2e.py

# E2E testnet4 tests -- 27 tests, requires funded testnet4 wallet (~30s)
# Parallel + serial signing with real testnet4 transactions
python3 tests/test_testnet4_e2e.py

# E2E with visible browser
python3 tests/test_psbt_builder.py --headed
python3 tests/test_regtest_e2e.py --headed
python3 tests/test_testnet4_e2e.py --headed

# Recover funds from a failed testnet4 test run
python3 tests/test_testnet4_e2e.py --recover
```

### Testnet4 Wallet Setup

The testnet4 E2E test needs a pre-funded wallet. Provide credentials via:

1. **Environment variables**: `TESTNET4_WIF` and `TESTNET4_ADDRESS`
2. **CLI arguments**: `--wif` and `--address`
3. **settings.json** in project root: `{"TESTNET4_WIF": "c...", "TESTNET4_ADDRESS": "tb1q..."}`

Fund the wallet at the [testnet4 faucet](https://mempool.space/testnet4/faucet).

### CLI Signing Tool

For hot wallet signing without Bitcoin Core:

```bash
pip install embit
python3 tools/sign-psbt.py unsigned.psbt <WIF-private-key>
# Outputs: unsigned-signed.psbt
```

### Known Issues

**Coldcard Q auto-finalizes P2WPKH inputs as P2PKH via QR**: When the Coldcard Q receives a PSBT via QR where all inputs have `partial_sigs`, it auto-finalizes and outputs a raw transaction. It incorrectly places P2WPKH witness signatures in scriptSig (P2PKH-style), causing "Witness requires empty scriptSig" on broadcast. USB signing (`ckcc sign`) does not have this issue. Workaround: WIF inputs are left unsigned at PSBT creation and signed in the browser during the combine step after the Coldcard returns its signed PSBT. Firmware: v1.4.0Q.

**`ckcc addr` blocks the Coldcard**: `ckcc addr` returns the address to the CLI immediately but displays it on the Coldcard screen, blocking USB until the user dismisses it. The Coldcard tests avoid this by using `ckcc pubkey` and deriving the address locally via embit.

### Prerequisites

- Python 3
- [Playwright](https://playwright.dev/python/): `pip install playwright && playwright install chromium`
- [embit](https://github.com/diybitcoin/embit): `pip install embit` (for `tools/sign-psbt.py` and Coldcard tests)
- [ckcc-protocol](https://github.com/Coldcard/ckcc-protocol): `pip install ckcc-protocol` (for real Coldcard MK4 tests only)
- Bitcoin Core v30+ (for regtest E2E tests only)

## Content Security Policy

Every page ships a strict `<meta http-equiv="Content-Security-Policy">` tag. It turns "a scan of
the code found no exfiltration call" into "no exfiltration connection can succeed, even one a scan
missed" -- for a page that handles WIF private keys, that's a meaningfully stronger guarantee.
`index.html`'s online policy allows scripts only from the page's own origin (`script-src 'self'`)
and network connections only to itself, `https://mempool.space`, and `localhost`/`127.0.0.1` on any
port over http or https (`connect-src 'self' https://mempool.space http://localhost:*
http://127.0.0.1:* https://localhost:* https://127.0.0.1:*` -- the last four entries exist for the
"Use your own node" custom-backend feature above, and are the entire allowlist a custom backend URL
is validated against); everything else -- images beyond `data:`/`blob:` canvases, frames beyond
the local `psbt-decoder/` submodule, forms, plugins -- is denied by `default-src 'none'` plus the
per-directive allowances. A meta CSP forbids inline `<script>` blocks and `onclick="..."`
attributes, which is why the app's logic lives in `app.js` (loaded via `<script type="module"
src="app.js">`) instead of inline, and why the donate button's navigation is wired up with
`addEventListener` in `app.js` rather than an inline handler. `tools/build-offline.py` swaps in an
even stricter policy for the offline build -- `connect-src 'none'` -- since once everything is
inlined into one file for Tails, there is genuinely no network resource left for it to reach. See
`CLAUDE.md`'s "Content Security Policy" section for the exact directive strings for every page and
the reasoning behind each one.

## Tech Stack

- **Frontend**: `index.html` + `app.js` (sweeper) + `donate.html` + `donate.js`, no build step. A strict `Content-Security-Policy` meta tag on every page (`script-src 'self'`, no inline scripts) is why the app logic lives in `app.js` rather than inline — see "Content Security Policy" above.
- **JS Libraries** (vendored locally into `vendor/deps.js`/`vendor/jsqr.js`, built from hash-pinned npm tarballs — see `vendor/pins.json`): [bitcoinjs-lib](https://github.com/bitcoinjs/bitcoinjs-lib) v7.0.1, [bip32](https://github.com/bitcoinjs/bip32) v5.0.1, [bs58check](https://github.com/bitcoinjs/bs58check) v3.0.1, [ecpair](https://github.com/bitcoinjs/ecpair) v3.0.0, [bbqr](https://github.com/coinkite/BBQr), [jsQR](https://github.com/cozmo/jsQR)
- **QR Generator**: Custom `qr_generator.js` (shared with [bitcoin-gift-paper-wallet](https://github.com/ObjSal/bitcoin-gift-paper-wallet))
- **Dev Server**: Python stdlib (`http.server`) + Bitcoin Core RPC
- **Tests**: [Playwright](https://playwright.dev/python/) (Python sync API)

## Support This Project

Building and maintaining open-source Bitcoin tools takes time, caffeine, and compute. If you find this project useful, consider buying me a coffee — with Bitcoin!

<div align="center">

**`bc1qrfagrsfrm8erdsmrku3fgq5yc573zyp2q3uje8`**

*This address was generated using [₿itcoin Gift Paper Wallet](https://objsal.github.io/bitcoin-gift-paper-wallet/)*

</div>

Your donation helps cover the cost of Claude (the AI that helped build this), keeps the coffee flowing, and fuels development of more open-source Bitcoin tools. No VC funding, no ads, no tracking — just open-source code and generous supporters like you.

## License

This project is provided as-is, without warranty of any kind. The author is not responsible for any loss of funds from transactions created with this tool. Always verify addresses, amounts, and fees before signing and broadcasting.
