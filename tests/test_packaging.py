"""Release readiness: build sdist + wheel, install into a fresh venv, run the console script and an offline smoke test.

Offline: the build uses the setuptools already installed for the interpreter running the tests (no build
isolation, no index), and the fresh venv installs the wheel with --no-index --no-deps (there are no
dependencies). Needs setuptools>=77 importable; otherwise the test is SKIPPED with the reason, never passed.
"""

import email.parser
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile

import watchtower
from watchtower.cli import build_parser

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ITEMS = ("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in", "watchtower", "examples", "tests")
UNIT = ROOT / "examples" / "nonce-watchtower-stream.service"


def _setuptools_ok():
    r = subprocess.run([sys.executable, "-c", "import setuptools, sys; v = tuple(int(x) for x in setuptools.__version__.split('.')[:2]); "
                        "sys.exit(0 if v >= (77, 0) else 1)"], capture_output=True)
    return r.returncode == 0


def _build(src, what, out):
    code = f"import setuptools.build_meta as b; print(b.build_{what}({str(out)!r}))"
    r = subprocess.run([sys.executable, "-c", code], cwd=src, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise AssertionError(f"build_{what} failed:\n{r.stdout[-3000:]}\n{r.stderr[-3000:]}")
    return out / r.stdout.strip().splitlines()[-1]


SMOKE = textwrap.dedent('''
    import base64, io, json, os, struct, sys, tempfile
    import watchtower
    from watchtower import cli
    from watchtower.notify import TelegramSink
    from watchtower.rpc import RpcClient
    from watchtower.stream import StreamWatcher

    # 1. It is the installed copy, not the source tree.
    assert os.path.realpath(watchtower.__file__).startswith(os.path.realpath(sys.prefix)), watchtower.__file__
    assert watchtower.__version__ == "0.3.0"

    from watchtower.base58 import b58decode
    SYS = "11111111111111111111111111111111"
    WALLET = "1nc1nerator11111111111111111111111111111111"     # clean
    COUNCIL = "Stake11111111111111111111111111111111111111"    # holds one nonce account
    NONCE = "SysvarRent111111111111111111111111111111111"

    def nonce_entry(pubkey, authority):
        raw = struct.pack("<II", 1, 1) + b58decode(authority) + b"\\x07" * 32 + struct.pack("<Q", 5000)
        return {"pubkey": pubkey, "account": {"owner": SYS, "lamports": 1, "data": [base64.b64encode(raw).decode(), "base64"]}}

    def transport(method, params):
        if method == "getProgramAccounts":
            auth = params[1]["filters"][1]["memcmp"]["bytes"]
            res = {SYS: [nonce_entry("Canary1111111111111111111111111111111111111", SYS)],
                   COUNCIL: [nonce_entry(NONCE, COUNCIL)]}.get(auth, [])
            if params[1].get("withContext"):
                res = {"context": {"slot": 100}, "value": res}
            return {"jsonrpc": "2.0", "id": 1, "result": res}
        if method == "getSlot":
            assert params == [{"commitment": "finalized"}], params
            return {"jsonrpc": "2.0", "id": 1, "result": 100}
        if method == "getBlockTime":
            import time
            return {"jsonrpc": "2.0", "id": 1, "result": int(time.time()) - 3}
        if method == "getTokenAccountsByOwner":
            return {"jsonrpc": "2.0", "id": 1, "result": {"context": {"slot": 100}, "value": []}}
        if method == "getSignaturesForAddress":
            return {"jsonrpc": "2.0", "id": 1, "result": []}
        raise AssertionError(method)

    # 2. Read-only guard is live in the installed package.
    try:
        RpcClient(transport=transport).call("sendTransaction", [])
        raise SystemExit("read-only guard missing")
    except PermissionError:
        pass

    # 3. A clean, complete scan through the real CLI entry point exits 0.
    cli._client = lambda *a, **k: RpcClient(transport=transport)
    sys.stdout = io.StringIO()
    rc = cli.main(["scan", WALLET, "--json"])
    report = json.loads(sys.stdout.getvalue())
    sys.stdout = sys.__stdout__
    assert rc == 0 and report["complete"] and report["nonce_coverage"]["status"] == "ok", (rc, report)

    # 4. Streaming mode: one connection, subscriptions confirmed, then a re-sync scan, state written, alert delivered.
    d = tempfile.mkdtemp()
    cfg_path = os.path.join(d, "w.toml")
    open(cfg_path, "w").write('[[wallets]]\\npubkey = "%s"\\n' % COUNCIL)
    cfg = cli.load_config(cfg_path)
    sent = []

    class Resp:
        status = 200
        def read(self, n=-1): return b'{"ok": true}'
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def opener(req, timeout):
        sent.append(json.loads(req.data)["text"])
        return Resp()

    sink = TelegramSink("123456789:" + "A" * 35, "-100123", opener=opener, sleep=lambda s: None)
    t = [0.0]
    stop = []

    class Conn:
        display = "wss://smoke"
        last_frame_at = 0.0
        def __init__(self): self.inbox, self.n = [], 0
        def request(self, m, p):
            self.n += 1; self.inbox.append({"jsonrpc": "2.0", "id": self.n, "result": self.n}); return self.n
        def recv(self, timeout):
            if self.inbox: return self.inbox.pop(0)
            stop.append(1); t[0] += timeout; return None
        def ping(self): pass
        def close(self): pass

    w = StreamWatcher(cfg, RpcClient(transport=transport), cfg["state_file"], "wss://smoke", cycle=cli.watch_cycle,
                      connect=lambda url: Conn(), sinks=[sink], out=io.StringIO(), clock=lambda: t[0],
                      sleep=lambda s: None, log=lambda m: None, should_stop=lambda: bool(stop))
    sys.stderr = io.StringIO()
    w.run()
    sys.stderr = sys.__stderr__
    assert w.connects == 1 and w.polls == [("resync", True)], (w.connects, w.polls)
    state = json.load(open(cfg["state_file"]))
    assert state["version"] == "0.3.0" and state["snapshot"]["coverage"]["stream"] == "ok", state["snapshot"]["coverage"]
    assert sent and "nonce-watchtower 0.3.0" in sent[0] and "existing_nonce_account" in sent[0], sent
    print("SMOKE OK")
''')


class CleanInstallTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _setuptools_ok():
            raise unittest.SkipTest("setuptools>=77 is not importable by this interpreter; the clean-install test "
                                    "did NOT run (pip install 'setuptools>=77' to run it)")
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix="wt-pkg-"))
        src = cls.tmp / "src"
        src.mkdir()
        for item in SOURCE_ITEMS:
            p = ROOT / item
            if p.is_dir():
                shutil.copytree(p, src / item, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.state.json"))
            else:
                shutil.copy2(p, src / item)
        dist = cls.tmp / "dist"
        dist.mkdir()
        cls.sdist = _build(src, "sdist", dist)
        # Build the wheel FROM the unpacked sdist: proves the sdist alone is a complete source release.
        with tarfile.open(cls.sdist) as tf:
            tf.extractall(cls.tmp / "unpacked", filter="data")
        unpacked = next((cls.tmp / "unpacked").iterdir())
        cls.wheel = _build(unpacked, "wheel", dist)
        cls.venv = cls.tmp / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(cls.venv)], check=True, capture_output=True, timeout=300)
        cls.py = cls.venv / "bin" / "python"
        r = subprocess.run([str(cls.py), "-m", "pip", "install", "--no-index", "--no-deps", "--disable-pip-version-check",
                            "-q", str(cls.wheel)], capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            raise AssertionError(f"pip install of the wheel failed:\n{r.stdout}\n{r.stderr}")
        cls.run_dir = cls.tmp / "elsewhere"  # not the source tree, so nothing can import from it
        cls.run_dir.mkdir()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_installed(self, *args, **kw):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("WATCHTOWER_", "PYTHON"))}
        return subprocess.run(list(args), cwd=self.run_dir, capture_output=True, text=True, timeout=120, env=env, **kw)

    def test_console_script_help_and_version(self):
        exe = str(self.venv / "bin" / "watchtower")
        r = self.run_installed(exe, "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        for cmd in ("scan", "watch", "stream", "alert-test"):
            self.assertIn(cmd, r.stdout)
        r = self.run_installed(exe, "--version")
        self.assertEqual(r.stdout.strip(), f"nonce-watchtower {watchtower.__version__}")
        self.assertEqual(self.run_installed(exe, "stream", "--help").returncode, 0)
        self.assertEqual(self.run_installed(exe, "scan", "not-a-key").returncode, 64)
        r = self.run_installed(str(self.py), "-I", "-m", "watchtower", "--version")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_offline_smoke_in_fresh_venv(self):
        r = self.run_installed(str(self.py), "-I", "-c", SMOKE)
        self.assertEqual(r.returncode, 0, f"{r.stdout}\n{r.stderr}")
        self.assertIn("SMOKE OK", r.stdout)

    def test_wheel_contents_and_metadata(self):
        with zipfile.ZipFile(self.wheel) as z:
            names = z.namelist()
            meta_name = next(n for n in names if n.endswith(".dist-info/METADATA"))
            meta = email.parser.Parser().parsestr(z.read(meta_name).decode())
            eps = z.read(next(n for n in names if n.endswith("entry_points.txt"))).decode()
        modules = {f"watchtower/{p.name}" for p in (ROOT / "watchtower").glob("*.py")}
        self.assertEqual({n for n in names if n.startswith("watchtower/")}, modules)
        self.assertFalse(any(n.startswith("tests/") for n in names))
        self.assertEqual(meta["Name"], "nonce-watchtower")
        self.assertEqual(meta["Version"], watchtower.__version__)
        self.assertEqual(meta["Version"], "0.3.0")
        self.assertEqual(meta["License-Expression"], "MIT")
        self.assertEqual(meta["Requires-Python"], ">=3.11")
        self.assertIsNone(meta["Requires-Dist"])  # stdlib only, by design
        self.assertEqual(meta["Description-Content-Type"], "text/markdown")
        self.assertIn("nonce-watchtower", meta.get_payload())
        self.assertTrue(any("github.com/clawboriclaw/nonce-watchtower" in u for u in meta.get_all("Project-URL")))
        self.assertIn("watchtower = watchtower.cli:main", eps)

    def test_sdist_is_complete_and_clean(self):
        with tarfile.open(self.sdist) as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            names = {m.name.split("/", 1)[1] for m in members}
            blobs = [tf.extractfile(m).read() for m in members]
        for need in ("pyproject.toml", "README.md", "LICENSE", "examples/nonce-watchtower-stream.service",
                     "examples/watchtower.env.example", "examples/wallets.example.toml", "tests/test_stream.py",
                     "tests/fixtures/gpa_canary.json"):
            self.assertIn(need, names)
        self.assertFalse(any(".venv" in n or n.endswith((".state.json", ".pyc")) for n in names))
        # Needles are split so this file does not match itself.
        for needle in (b"/ho" + b"me/", b"@gm" + b"ail"):
            for b in blobs:
                self.assertNotIn(needle, b)
        # Internal reviewer/agent names must not ship (neutral wording: "independent review").
        # The pattern is assembled so this file does not match itself.
        banned = re.compile(r"\b(" + "|".join(["Av" + "a", "K" + "3", "Oc" + "to", "Cla" + "ude"]) + r")\b")
        for m, b in zip(members, blobs):
            hit = banned.search(b.decode("utf-8", "replace"))
            self.assertIsNone(hit, f"{m.name}: contains {hit.group(0) if hit else ''}")


class SystemdExampleTest(unittest.TestCase):
    def test_unit_runs_stream_with_flags_the_cli_accepts(self):
        text = UNIT.read_text()
        lines = text.replace("\\\n", " ").splitlines()
        execs = [ln.split("=", 1)[1] for ln in lines if ln.startswith("ExecStart=")]
        self.assertEqual(len(execs), 1)
        argv = shlex.split(execs[0])
        self.assertTrue(argv[0].endswith("/watchtower"))
        self.assertEqual(argv[1], "stream")
        args = build_parser().parse_args(argv[1:])  # raises SystemExit on a flag the CLI does not have
        self.assertEqual(args.resync_interval, 300)
        for need in ("Restart=always", "EnvironmentFile=", "DynamicUser=yes", "StateDirectory=nonce-watchtower",
                     "NoNewPrivileges=yes", "ProtectSystem=strict"):
            self.assertIn(need, text)
        self.assertTrue(args.state.startswith("/var/lib/nonce-watchtower/"))

    def test_env_example_names_match_config_defaults(self):
        from watchtower.config import ENV_NAME_KEYS
        text = (ROOT / "examples" / "watchtower.env.example").read_text()
        for name in ENV_NAME_KEYS.values():
            self.assertIn(name, text)


if __name__ == "__main__":
    unittest.main()
