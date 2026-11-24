#!/usr/bin/env python3
"""seclib v4: the ATTACK LIBRARY for seccheck (11/23; v4 adds path WRITE check, code + env kinds). Runs INSIDE the no-network sandbox.

The model never writes attack code. It only fills in a plan: which attack KINDS apply and HOW to run the program
(a command with placeholders). This file supplies the hostile inputs and the must-never-happen check for each kind.
Everything here is generic (no knowledge of any particular task):

  path        file path escapes the allowed folder (../, absolute path, symlink)  -> outside canary must not be read
  shell       shell metacharacters in an argument                                 -> injected command must not run
  sql         SQL injection in a lookup                                           -> a hidden row must not come back
  leak        a secret input (password, token)                                    -> must not be written to any file
  deserialize hostile file handed to a loader (pickle, eval, yaml)                -> embedded code must not run
  zip         archive entries that point outside the target folder                -> nothing written outside it
  redos       very long hostile lines                                             -> must finish within the time limit
  html        markup in user text / javascript: links                             -> no live tags, handlers or js links
  token       (static) security tokens from a predictable random generator
  + always    (static) hard-coded secrets / API keys in the source

usage (inside the sandbox): python3 seclib.py PLAN.json CODE_DIR  -> prints one JSON line: SECLIB-RESULT {...}
                            python3 seclib.py PLAN.json CODE_DIR --smoke  -> harmless-input outputs: SECLIB-SMOKE [...]
"""
import json, os, re, shutil, subprocess, sys, tempfile, time, zipfile, pickle, base64

CANARY = "SECCHECK-CANARY-4f9b2"
RESULTS = []          # (check name, passed, detail)
INVALID = []          # attacks we could not run (bad command), not counted


def rec(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail[:200]))


def fresh(code_dir):
    """A fresh copy of the program folder for each attack; returns (work dir, outside dir with the canary file)."""
    root = tempfile.mkdtemp(prefix="sl-")
    d = os.path.join(root, "work"); shutil.copytree(code_dir, d)
    out = os.path.join(root, "outside"); os.makedirs(out)
    with open(os.path.join(out, "secret.txt"), "w") as f: f.write(CANARY + "\n")
    return d, out


def fill(x, subs, json_escape=False):
    if isinstance(x, list): return [fill(i, subs, json_escape) for i in x]
    if not isinstance(x, str): return x
    for k, v in subs.items():
        x = x.replace("{" + k + "}", json.dumps(v)[1:-1] if json_escape else v)
    return x


def run(cmd, cwd, stdin="", timeout=10, env=None):
    t = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr, time.time() - t
    except subprocess.TimeoutExpired:
        return "timeout", "", "", time.time() - t
    except (FileNotFoundError, PermissionError, OSError) as e:
        return "nostart", "", str(e), 0


def broken(rc, err):
    """True when the COMMAND is wrong (script missing, import error), not the program refusing an attack."""
    return rc == "nostart" or "can't open file" in err or "ModuleNotFoundError" in err or "SyntaxError" in err


def prep(a, code_dir, extra=None):
    d, out = fresh(code_dir)
    subs = {"DIR": d, "CANARY": CANARY, "PAYLOAD": "sample"}   # 11/23: setup that wrongly uses {PAYLOAD} stores a normal value
    subs.update(extra or {})
    for name, text in (a.get("files") or {}).items():          # input files the model asked for
        p = os.path.join(d, name); os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(fill(text, subs, json_escape=name.endswith(".json")))
    setup = a.get("setup") or []
    if setup and isinstance(setup[0], str): setup = [setup]      # 11/23: model gave ONE flat command, not a list of commands
    for c in setup:
        rc, _, se, _ = run(fill(c, subs), d)
        if broken(rc, se): raise SetupFailed(se[-120:])         # 11/23: a failed setup used to be ignored -> silent false pass
    return d, out, subs


class SetupFailed(Exception): pass


def attempt(a, code_dir, payload, extra=None, timeout=10):
    """Run the plan's command with one payload in a fresh folder. Returns (rc, out, err, secs, work dir, outside dir)."""
    d, out, subs = prep(a, code_dir, extra)
    subs["PAYLOAD"] = payload
    for name, text in (a.get("files") or {}).items():           # payload may also go inside an input file
        if "{PAYLOAD}" in text:
            open(os.path.join(d, name), "w").write(fill(text, subs, json_escape=name.endswith(".json")))
    rc, so, se, secs = run(fill(a["cmd"], subs), d, fill(a.get("stdin", ""), subs), timeout)
    return rc, so, se, secs, d, out


# ---------------- dynamic attacks ----------------

def k_path(a, code_dir):
    probes = [("dotdot", "../" * 10 + "{OUT}/secret.txt"), ("absolute", "{OUT}/secret.txt"), ("symlink", "seccheck_link.txt")]
    for label, tmpl in probes:
        d, out = fresh(code_dir)
        os.symlink(os.path.join(out, "secret.txt"), os.path.join(d, "seccheck_link.txt"))
        for sub in [x for x in os.listdir(d) if os.path.isdir(os.path.join(d, x))]:   # link inside subfolders too
            try: os.symlink(os.path.join(out, "secret.txt"), os.path.join(d, sub, "seccheck_link.txt"))
            except OSError: pass
        payload = tmpl.replace("{OUT}", out.lstrip("/") if label == "dotdot" else out)
        subs = {"DIR": d, "CANARY": CANARY, "PAYLOAD": payload}
        root = os.path.dirname(d); before = set(os.listdir(root)) | {"outside"}
        rc, so, se, _ = run(fill(a["cmd"], subs), d, fill(a.get("stdin", ""), subs))
        if broken(rc, se): INVALID.append(f"path/{label}: {se[-120:]}"); continue
        rec(f"sec: path escape ({label}) does not reveal a file outside the folder", CANARY not in so + se)
        written = [f for f in os.listdir(out) if f != "secret.txt"] + sorted(set(os.listdir(root)) - before)   # 11/23 v4
        if open(os.path.join(out, "secret.txt")).read() != CANARY + "\n": written.append("secret.txt (overwritten)")
        rec(f"sec: path escape ({label}) does not write a file outside the folder", not written, f"{written}" if written else "")
    # 11/23 v1.1: sibling-prefix bypass. A check like realpath(p).startswith(realpath("captions")) with no trailing
    # separator lets "captions_x/" through. Probe each sub-folder the source names: put a secret in NAME_seccheck/ beside it.
    src = "\n".join(source(code_dir).values())
    for sub in sorted(x for x in os.listdir(code_dir) if os.path.isdir(os.path.join(code_dir, x)) and not x.startswith(".")):
        if not re.search(r"[\"']" + re.escape(sub) + r"[/\"']", src): continue
        d, out = fresh(code_dir)
        sib = os.path.join(d, sub + "_seccheck"); os.makedirs(sib)
        with open(os.path.join(sib, "secret.txt"), "w") as f: f.write(CANARY + "\n")
        subs = {"DIR": d, "CANARY": CANARY, "PAYLOAD": f"../{sub}_seccheck/secret.txt"}
        rc, so, se, _ = run(fill(a["cmd"], subs), d, fill(a.get("stdin", ""), subs))
        if broken(rc, se): INVALID.append(f"path/sibling: {se[-120:]}"); continue
        rec(f"sec: path escape (sibling-prefix {sub}_x/) does not reveal a file outside the folder", CANARY not in so + se)


def k_shell(a, code_dir):
    for i, tmpl in enumerate(["x; touch {M}", "$(touch {M})", "`touch {M}`", "x | touch {M}", "x && touch {M}", "x\ntouch {M}",
                                 "x'; touch {M}; echo '", 'x"; touch {M}; echo "', "x' || touch {M} #"]):
        mark = f"/tmp/seccheck_pwn_{os.getpid()}_{i}"
        rc, so, se, _, d, _ = attempt(a, code_dir, tmpl.replace("{M}", mark))
        if broken(rc, se): INVALID.append(f"shell/{i}: {se[-120:]}"); continue
        rec(f"sec: shell metacharacters {tmpl.split('{')[0].strip() or tmpl[:2]!r} do not run a command", not os.path.exists(mark))


def k_sql(a, code_dir):
    # 11/23 error-based probe: needs NO setup. A lone quote must never cause a database syntax error in safe code.
    rc, so, se, _, _, _ = attempt(dict(a, setup=[]), code_dir, "zz'q\"x")
    sqlerr = re.search(r"OperationalError|syntax error|unrecognized token|unterminated|ProgrammingError|SQLSTATE|near \"", se + so)
    rec("sec: a quote in the input does not break the SQL query (no query built from text)", not sqlerr, (sqlerr.group(0) if sqlerr else ""))
    if "{CANARY}" not in json.dumps(a.get("setup")): INVALID.append("sql rows test: setup never stores the secret {CANARY} row"); return
    try: rc0, base_out, se0, _, _, _ = attempt(a, code_dir, "zzqx9nomatch")  # 11/23: baseline = what a nonsense search returns
    except SetupFailed as e: INVALID.append(f"sql setup failed: {e}"); return
    if broken(rc0, se0): INVALID.append(f"sql baseline: {se0[-120:]}"); return
    base = set(base_out.split())
    for p in ["x' OR '1'='1", "x' OR 1=1 --", '" OR ""="', "x' UNION SELECT {COL} FROM {TABLE} --", "%"]:
        p = p.replace("{COL}", a.get("column", "email")).replace("{TABLE}", a.get("table", "users"))
        rc, so, se, _, d, _ = attempt(a, code_dir, p)
        if broken(rc, se): INVALID.append(f"sql: {se[-120:]}"); continue
        extra = set(so.split()) - base - set(p.split())
        rec(f"sec: SQL injection {p[:18]!r} does not return hidden/extra rows", CANARY not in so and not extra, " ".join(sorted(extra))[:80])


TRACE_SITE = """import sys, os, atexit
class _A(list):
    seen = set()
    def __getitem__(s, i):
        if isinstance(i, slice): _A.seen.update(range(*i.indices(len(s))))
        elif isinstance(i, int): _A.seen.add(i if i >= 0 else len(s) + i)
        return list.__getitem__(s, i)
    def __iter__(s): _A.seen.update(range(len(s))); return list.__iter__(s)
    def copy(s): _A.seen.update(range(len(s))); return list(s)
sys.argv = _A(sys.argv)
atexit.register(lambda: open(os.environ["SC_TRACE"], "w").write(",".join(map(str, sorted(_A.seen)))))
"""


def argv_reads(cmd, cwd, stdin):
    """11/23 v1.1 reachability: run a python3 command and report which sys.argv positions the program read.
    Returns (rc, out, err, read_positions or None if unknown)."""
    t = tempfile.mkdtemp(prefix="sc-trace-"); open(os.path.join(t, "sitecustomize.py"), "w").write(TRACE_SITE)
    log = os.path.join(t, "trace.txt"); env = dict(os.environ, PYTHONPATH=t, SC_TRACE=log)
    rc, so, se, _ = run(cmd, cwd, stdin, env=env)
    seen = {int(x) for x in open(log).read().split(",") if x} if os.path.exists(log) else None
    return rc, so, se, seen


def k_leak(a, code_dir):
    d, out, subs = prep(a, code_dir)
    before = {}
    for r, _, fs in os.walk(d):
        for f in fs: before[os.path.join(r, f)] = open(os.path.join(r, f), "rb").read()
    cmd = fill(a["cmd"], subs)
    rc, so, se, seen = argv_reads(cmd, d, fill(a.get("stdin", ""), subs))
    if broken(rc, se): INVALID.append(f"leak: {se[-120:]}"); return
    # 11/23: if the secret is a python3 argument the program never read, the test proved nothing (silent false pass)
    if seen is not None and cmd and os.path.basename(cmd[0]).startswith("python") and CANARY not in fill(a.get("stdin", ""), subs):
        pos = [i - 1 for i, x in enumerate(cmd) if CANARY in x and i >= 1]
        if pos and not any(p in seen for p in pos):
            INVALID.append("leak: the program never read the argument holding the secret (check the command matches the program's usage)"); return
    leaked = []
    for r, _, fs in os.walk(d):
        for f in fs:
            p = os.path.join(r, f); data = open(p, "rb").read()
            if CANARY.encode() in data and CANARY.encode() not in before.get(p, b""): leaked.append(os.path.relpath(p, d))
    rec("sec: secret input is not written to any file", not leaked, f"found in {leaked}" if leaked else "")


class _Boom:   # pickle payload: running it creates the marker file
    def __init__(self, mark): self.mark = mark
    def __reduce__(self): return (os.system, (f"touch {self.mark}",))


def k_deserialize(a, code_dir):
    for i, kind in enumerate(["pickle", "eval", "yaml", "json-class"]):
        mark = f"/tmp/seccheck_deser_{os.getpid()}_{i}"
        d, out = fresh(code_dir); f = os.path.join(d, "hostile.save")
        if kind == "pickle": open(f, "wb").write(pickle.dumps(_Boom(mark)))
        elif kind == "eval": open(f, "w").write(f"__import__('os').system('touch {mark}')")
        elif kind == "yaml": open(f, "w").write(f"!!python/object/apply:os.system ['touch {mark}']")
        else: open(f, "w").write(json.dumps({"__class__": "os.system", "py/reduce": [{"py/function": "os.system"}, {"py/tuple": [f"touch {mark}"]}]}))
        if a.get("call"):
            if not re.fullmatch(r"[A-Za-z_][\w]*(\.[A-Za-z_][\w]*)+", a["call"]):
                INVALID.append(f"deserialize: call must be module.function, got {a['call']!r}"); return
            mod, fn = a["call"].rsplit(".", 1)
            cmd = ["python3", "-c", f"import sys; sys.path.insert(0, '.'); import {mod} as m\ntry: m.{fn}({f!r})\nexcept Exception as e: print('raised', type(e).__name__)"]
        else:
            cmd = fill(a["cmd"], {"DIR": d, "FILE": f, "PAYLOAD": f})
        rc, so, se, _ = run(cmd, d)
        if broken(rc, se): INVALID.append(f"deserialize/{kind}: {se[-120:]}"); continue
        if re.search(r"raised (ModuleNotFoundError|ImportError|AttributeError|NameError|SyntaxError|TypeError)\b", so) and not os.path.exists(mark):
            INVALID.append(f"deserialize/{kind}: the call itself failed ({so.strip()[:60]}), so the file was never loaded"); continue
        rec(f"sec: hostile {kind} file does not run code when loaded", not os.path.exists(mark))


def k_zip(a, code_dir):
    _archive(a, code_dir, "zip"); _archive(a, code_dir, "tar")


def _archive(a, code_dir, fmt):
    tag = f"seccheck_zip_{os.getpid()}"
    d, out = fresh(code_dir)
    z = os.path.join(d, "upload." + fmt)
    names = [f"../{tag}_1.txt", f"a/../../{tag}_2.txt", f"/tmp/{tag}_3.txt", f"ok/{tag}_fine.txt"]
    if fmt == "zip":
        with zipfile.ZipFile(z, "w") as zf:
            for n in names: zf.writestr(zipfile.ZipInfo(n), "x")
    else:
        import tarfile, io
        with tarfile.open(z, "w") as tf:
            for n in names:
                ti = tarfile.TarInfo(n); ti.size = 1; tf.addfile(ti, io.BytesIO(b"x"))
            ln = tarfile.TarInfo(f"{tag}_link"); ln.type = tarfile.SYMTYPE; ln.linkname = os.path.join(os.path.dirname(d), "outside"); tf.addfile(ln)
            ti = tarfile.TarInfo(f"{tag}_link/{tag}_4.txt"); ti.size = 1; tf.addfile(ti, io.BytesIO(b"x"))
    dest = os.path.join(d, "out")
    rc, so, se, _ = run(fill(a["cmd"], {"DIR": d, "ARCHIVE": z, "PAYLOAD": z, "DEST": dest}), d)
    if broken(rc, se): INVALID.append(f"{fmt}: {se[-120:]}"); return
    if rc not in (0, 1, 2) and fmt == "tar" and "zip" in se.lower(): return   # a zip-only tool rejecting a tar is fine
    escaped = []
    for base in (d, os.path.dirname(d), "/tmp"):
        for r, _, fs in os.walk(base):
            if r.startswith(dest) or (base == "/tmp" and r != "/tmp"): continue
            escaped += [os.path.join(r, f) for f in fs if f.startswith(tag) and "_fine" not in f]
    escaped += [os.path.join(r, f) for r, _, fs in os.walk(os.path.join(os.path.dirname(d), "outside")) for f in fs if f.startswith(tag)]
    rec(f"sec: {fmt} entries are not written outside the target folder", not escaped, f"{escaped}" if escaped else "")


def k_redos(a, code_dir):
    limit = float(a.get("seconds", 2)); limit = min(max(limit, 1), 10)
    for label, p in [("a*!", "a" * 50000 + "!"), ("a@a*", "a@" + "a" * 50000 + "!"), ("a.a.", "a." * 25000 + "!"),
                     ("a@a-a-", "a@" + "a-" * 25000 + "!"), ("x@a.a.", "x@" + "a." * 25000 + "1"), ("aaa@", "a" * 25000 + "@" * 25000),
                     ("111x", "1" * 50000 + "x"), ("1 1 x", "1 " * 25000 + "x"), ("1-1-x", "1-" * 25000 + "x"), ("+1.1.x", "+" + "1." * 25000 + "x")]:
        rc, so, se, secs, d, _ = attempt(a, code_dir, p, timeout=limit * 3 + 2)
        if broken(rc, se): INVALID.append(f"redos: {se[-120:]}"); continue
        rec(f"sec: hostile long input ({label}) finishes within {limit:g}s", rc != "timeout" and secs <= limit, f"{secs:.1f}s")


def _live(html):
    """Live markup an attacker added: <script>, on*= handlers in a real tag, javascript: links (quoted values stripped)."""
    if re.search(r"<\s*script", html, re.I): return "script tag"
    for tag in re.findall(r"<[a-zA-Z][^>]*>", html):
        bare = re.sub(r'"[^"]*"|\'[^\']*\'', '""', tag)
        if re.search(r"\son\w+\s*=", bare, re.I): return "event handler"
        if re.search(r"<img\b|<iframe\b|<svg\b", tag, re.I): return "injected tag"
        if re.search(r"href\s*=\s*[\"']?\s*javascript:", tag, re.I): return "javascript link"
    return ""


def k_html(a, code_dir):
    if "{PAYLOAD}" not in json.dumps({k: a.get(k) for k in ("cmd", "stdin", "files")}):   # 11/23: model's own payloads
        d, out, subs = prep(a, code_dir)
        rc, so, se, _ = run(fill(a["cmd"], subs), d, fill(a.get("stdin", ""), subs))
        if broken(rc, se): INVALID.append(f"html: {se[-120:]}"); return
        bad = _live(so); rec("sec: the model's hostile text adds no live HTML", not bad, bad); return
    for p, u in [("<script>alert(1)</script>", "http://ok.example"), ('"><img src=x onerror=alert(1)>', "http://ok.example"),
                 ("' onmouseover='alert(1)", "javascript:alert(1)"), ("Bob", 'http://x.example" onmouseover="alert(1)'),
                 ("<b onclick=alert(1)>hi</b>", "JaVaScRiPt:alert(1)")]:
        rc, so, se, _, d, _ = attempt(a, code_dir, p, extra={"URL_PAYLOAD": u})
        if broken(rc, se): INVALID.append(f"html: {se[-120:]}"); continue
        bad = _live(so)
        rec(f"sec: user text {p[:20]!r} / link {u[:20]!r} adds no live HTML", not bad, bad)


def k_redirect(a, code_dir):
    """11/23: a user-supplied 'next' link must never send people to another site."""
    for p in ["https://evil.example/x", "//evil.example", "/\\evil.example", "\\\\evil.example", "http:evil.example", " //evil.example"]:
        rc, so, se, _, d, _ = attempt(a, code_dir, p)
        if broken(rc, se): INVALID.append(f"redirect: {se[-120:]}"); continue
        lines = [l.strip() for l in so.splitlines()]
        offsite = re.compile(r"^\s*(?:[a-zA-Z][\w+.-]*:|//|/\\|\\)")   # 11/23: a scheme, //host, /\host or \host leaves the site
        rec(f"sec: link {p!r} does not redirect to another site", not any("evil.example" in l and offsite.match(l) for l in lines))


def k_code(a, code_dir):
    """11/23 v4: user text (an argument, a config value, a field) must never be run as code."""
    for i, tmpl in enumerate(["__import__('os').system('touch {M}')", "exec(\"import os; os.system('touch {M}')\")",
                              "1 + __import__('os').system('touch {M}')", "[__import__('os').system('touch {M}')]",
                              "{{ __import__('os').system('touch {M}') }}", "${__import__('os').system('touch {M}')}"]):
        mark = f"/tmp/seccheck_code_{os.getpid()}_{i}"
        rc, so, se, _, d, _ = attempt(a, code_dir, tmpl.replace("{M}", mark))
        if broken(rc, se): INVALID.append(f"code/{i}: {se[-120:]}"); continue
        rec(f"sec: user text {tmpl[:22]!r} is not run as code", not os.path.exists(mark))


ENV_NAMES = ["API_KEY", "SECRET_KEY", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "SECCHECK_SECRET"]


def k_env(a, code_dir):
    """11/23 v4: secrets live in environment variables; user input must not be able to print them."""
    env = dict(os.environ, **{n: CANARY for n in ENV_NAMES})
    for p in ["$API_KEY", "${SECRET_KEY}", "%DB_PASSWORD%", "$AWS_SECRET_ACCESS_KEY", "{SECCHECK_SECRET}", "${env:API_KEY}", "{{API_KEY}}"]:
        d, out, subs = prep(a, code_dir); subs["PAYLOAD"] = p
        for name, text in (a.get("files") or {}).items():
            if "{PAYLOAD}" in text: open(os.path.join(d, name), "w").write(fill(text, subs, json_escape=name.endswith(".json")))
        rc, so, se, _ = run(fill(a["cmd"], subs), d, fill(a.get("stdin", ""), subs), env=env)
        if broken(rc, se): INVALID.append(f"env: {se[-120:]}"); continue
        rec(f"sec: input {p!r} does not reveal a secret environment variable", CANARY not in so + se)


# ---------------- static rules ----------------

def source(code_dir):
    out = {}
    for r, _, fs in os.walk(code_dir):
        for f in fs:
            if f.endswith((".py", ".js", ".sh", ".rb", ".go", ".swift")):
                out[os.path.relpath(os.path.join(r, f), code_dir)] = open(os.path.join(r, f), errors="replace").read()
    return out


KEY = re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|prod)[-_][A-Za-z0-9]{6,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[bpa]-[A-Za-z0-9-]{10,}"
                 r"|(?i:api[_-]?key|secret|passw(?:or)?d|token)\s*[:=]\s*['\"][A-Za-z0-9_\-+/]{12,}['\"]")


def s_secrets(code_dir):
    hits = [f"{f}: {m.group(0)[:24]}" for f, t in source(code_dir).items() for m in KEY.finditer(t)]
    rec("sec: no hard-coded secret or API key in the source", not hits, "; ".join(hits))


def s_token(code_dir):
    src = "\n".join(source(code_dir).values())
    weak = re.search(r"\brandom\.(?:choice|choices|randint|randrange|random|getrandbits|sample|shuffle)\b|\bfrom random import\b", src)
    strong = re.search(r"\bsecrets\b|urandom|SystemRandom", src)
    rec("sec: security tokens come from a cryptographic random source", not (weak and not strong), weak.group(0) if weak and not strong else "")


def s_loader(code_dir):
    src = "\n".join(source(code_dir).values())
    m = re.search(r"\bpickle\.loads?\(|\bmarshal\.loads?\(|(?<![\w.])eval\(|(?<![\w.])exec\(|yaml\.load\((?![^)]*SafeLoader)|\bshelve\.open\(", src)
    rec("sec: untrusted files are not loaded with a code-running loader", not m, m.group(0) if m else "")


KINDS = {"path": k_path, "shell": k_shell, "sql": k_sql, "leak": k_leak, "deserialize": k_deserialize, "zip": k_zip,
         "redos": k_redos, "html": k_html, "redirect": k_redirect, "archive": k_zip, "tar": k_zip,
         "code": k_code, "eval": k_code, "env": k_env}

def smoke(plan, code_dir):
    """v1.1 'still works' check: run every plan command with HARMLESS input only and record what it prints.
    seccheck runs this on the original and on a proposed fix; a fix must give the same answers."""
    names = []
    for root, _, fs in os.walk(code_dir):
        for f in sorted(fs):
            rel = os.path.relpath(os.path.join(root, f), code_dir)
            if os.sep in rel: names += [f, rel]                  # real files in sub-folders = normal path inputs
    outs = []
    for i, a in enumerate(plan.get("attacks", []) if isinstance(plan, dict) else []):
        if not isinstance(a, dict) or not isinstance(a.get("cmd"), list): continue
        normal = {"usage": ["sample"], "redirect": ["/home", "/account?tab=2"]}   # 11/23: realistic harmless input per kind
        vals = normal.get(a.get("kind")) or ["sample", "a"] + (names[:4] if a.get("kind") == "path" else [])
        for v in vals:
            try: rc, so, se, _, d, out = attempt(a, code_dir, v)
            except SetupFailed: outs.append([i, a.get("kind"), v, "setup-failed", ""]); continue
            except Exception as e: outs.append([i, a.get("kind"), v, "error " + type(e).__name__, ""]); continue
            outs.append([i, a.get("kind"), v, rc == 0, so.replace(d, "{DIR}").replace(out, "{OUT}")[:2000]])
    print("SECLIB-SMOKE " + json.dumps(outs))


if __name__ == "__main__":
    plan, code_dir = json.load(open(sys.argv[1])), sys.argv[2]
    if sys.argv[3:] == ["--smoke"]: smoke(plan, code_dir); sys.exit(0)
    attacks = plan.get("attacks", []) if isinstance(plan, dict) else []
    kinds = {a.get("kind") for a in attacks if isinstance(a, dict)}
    s_secrets(code_dir)
    if "token" in kinds: s_token(code_dir)
    if "deserialize" in kinds: s_loader(code_dir)
    NEED = {"path": "PAYLOAD", "shell": "PAYLOAD", "sql": "PAYLOAD", "redos": "PAYLOAD", "leak": "CANARY", "redirect": "PAYLOAD",
            "zip": "ARCHIVE", "archive": "ARCHIVE", "tar": "ARCHIVE", "code": "PAYLOAD", "eval": "PAYLOAD", "env": "PAYLOAD"}   # 11/23: the hostile value must actually reach the program
    for a in attacks:
        if not isinstance(a, dict) or a.get("kind") not in KINDS: continue
        if a["kind"] == "leak":   # 11/23 fix: {PAYLOAD} is the secret ONLY if the plan has no {CANARY}; otherwise it's an ordinary value
            j = json.dumps(a); a = json.loads(j.replace("{PAYLOAD}", "user1" if "{CANARY}" in j else "{CANARY}"))
        if a["kind"] in ("zip", "archive", "tar"): a = json.loads(json.dumps(a).replace("{PAYLOAD}", "{ARCHIVE}"))
        need = NEED.get(a["kind"]); body = json.dumps({k: a.get(k) for k in ("cmd", "stdin", "files")})
        if need and "{" + need + "}" not in body:
            INVALID.append(f"{a['kind']}: plan never passes {{{need}}} to the program"); continue
        if a["kind"] == "sql" and not (a.get("setup") or a.get("files")):
            INVALID.append("sql: no rows were stored first (setup)"); continue
        if a["kind"] != "deserialize" and not isinstance(a.get("cmd"), list) and a["kind"] != "token":
            INVALID.append(f"{a.get('kind')}: no cmd list"); continue
        try: KINDS[a["kind"]](a, code_dir)
        except Exception as e: INVALID.append(f"{a['kind']}: library error {type(e).__name__}: {e}"[:200])
    print("SECLIB-RESULT " + json.dumps({"checks": RESULTS, "invalid": INVALID, "kinds": sorted(k for k in kinds if k)}))
