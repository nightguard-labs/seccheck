"""seccheck report: turns check results into a Markdown report a person can act on.
Each finding gets: what it is (CWE + OWASP name), the evidence, how to reproduce it, and the standard fix."""
import datetime, json, re

# (pattern in the check name, plan kind, title, CWE, OWASP Top 10 2021, standard fix)
RULES = [
    (r"path escape .* reveal", "path", "Path traversal (read)", "CWE-22", "A01 Broken Access Control",
     "Resolve the real path and refuse anything outside the allowed folder. Compare whole folders, not text prefixes (startswith lets 'captions_evil/' through): base = os.path.realpath('captions'); full = os.path.realpath(os.path.join(base, name)); if os.path.commonpath([base, full]) != base: refuse."),
    (r"path escape .* write", "path", "Path traversal (write)", "CWE-22", "A01 Broken Access Control",
     "Same as above, before opening for writing. Build the target from a fixed folder plus a checked file name only."),
    (r"shell metacharacters", "shell", "OS command injection", "CWE-78", "A03 Injection",
     "Never build a shell string from user input. Use subprocess.run([...]) with a list of arguments and shell=False, and validate the value against an allow-list."),
    (r"quote in the input does not break the SQL", "sql", "SQL injection (query built from text)", "CWE-89", "A03 Injection",
     "Use parameterized queries: cursor.execute('... WHERE name LIKE ?', ('%' + word + '%',)). Never put user text into the SQL string with f-strings, + or %."),
    (r"SQL injection", "sql", "SQL injection (hidden rows exposed)", "CWE-89", "A03 Injection",
     "Use parameterized queries (? placeholders). For LIKE searches ALSO escape the wildcards, or a visitor typing % sees every row: word = word.replace('\\\\', '\\\\\\\\').replace('%', '\\\\%').replace('_', '\\\\_'); cursor.execute(\"... WHERE name LIKE ? ESCAPE '\\\\'\", ('%' + word + '%',))"),
    (r"secret input is not written", "leak", "Secret written to a file or log", "CWE-532", "A09 Security Logging and Monitoring Failures",
     "Never log or save passwords, keys, tokens or card numbers. Store only a salted hash (passwords) or a masked value (last 4 digits)."),
    (r"hostile .* file does not run code", "deserialize", "Unsafe deserialization", "CWE-502", "A08 Software and Data Integrity Failures",
     "Load untrusted files with a data-only format: json.load, yaml.safe_load. Never pickle.load or eval on data from users."),
    (r"entries are not written outside", "archive", "Archive path traversal (zip/tar slip)", "CWE-22", "A01 Broken Access Control",
     "Check every member's final path is inside the target folder before extracting. Skip symlinks and absolute names. For tar, use tarfile's data filter."),
    (r"hostile long input", "redos", "Regular expression denial of service (ReDoS)", "CWE-1333", "A04 Insecure Design",
     "Remove nested quantifiers like (a+)+ or (\\d+)*. Limit input length before matching, or use a linear-time regex engine."),
    (r"adds no live HTML", "html", "Cross-site scripting (XSS)", "CWE-79", "A03 Injection",
     "Escape user text with html.escape(text, quote=True) before putting it in HTML, and allow only http/https links."),
    (r"does not redirect to another site", "redirect", "Open redirect", "CWE-601", "A01 Broken Access Control",
     "Only redirect to relative paths that start with a single '/', or to an allow-list of your own hosts. Reject //, \\ and scheme: links."),
    (r"is not run as code", "code", "Code injection", "CWE-94", "A03 Injection",
     "Never eval/exec user text. Use a real parser (ast.literal_eval for literals, a small expression parser for formulas)."),
    (r"environment variable", "env", "Secret exposed from environment variables", "CWE-526", "A01 Broken Access Control",
     "Don't expand user input against os.environ. Substitute only from an explicit allow-list of safe values."),
    (r"hard-coded secret", None, "Hard-coded secret", "CWE-798", "A07 Identification and Authentication Failures",
     "Read secrets from the environment or a secrets manager at run time. Rotate any key that was ever committed."),
    (r"cryptographic random", None, "Guessable security token", "CWE-338", "A02 Cryptographic Failures",
     "Use the secrets module (secrets.token_urlsafe(32)) for tokens, codes and passwords. Never use random."),
    (r"code-running loader", None, "Untrusted file loaded with a code-running loader", "CWE-502", "A08 Software and Data Integrity Failures",
     "Use json.load or yaml.safe_load for files that may come from strangers."),
]


def _rule(name):
    for pat, kind, title, cwe, owasp, fix in RULES:
        if re.search(pat, name): return kind, title, cwe, owasp, fix
    return None, "Security check failed", "", "", "Review the check named above."


def build(r, task, code_dir, model, fx=None):
    fails = [(n, d) for n, ok, d in r.get("checks", []) if not ok]
    plan = {a.get("kind"): a for a in (r.get("plan") or {}).get("attacks", []) if isinstance(a, dict)}
    out = ["# seccheck report", "",
           f"- **Code:** `{code_dir}`", f"- **Task:** `{task}`", f"- **Checker model:** `{model}`",
           f"- **Date:** {datetime.date.today().isoformat()}",
           f"- **Verdict:** **{r['verdict']}** ({len(fails)} finding(s), {len(r.get('checks', []))} checks run, {len(r.get('invalid', []))} skipped)", ""]
    groups = {}
    for n, d in fails:
        kind, title, cwe, owasp, fix = _rule(n)
        groups.setdefault(title, {"kind": kind, "cwe": cwe, "owasp": owasp, "fix": fix, "checks": []})["checks"].append((n, d))
    for i, (title, g) in enumerate(groups.items(), 1):
        out += [f"## {i}. {title}" + (f" ({g['cwe']})" if g["cwe"] else ""), ""]
        if g["owasp"]: out += [f"**OWASP Top 10:** {g['owasp']}", ""]
        out += ["**Evidence (failed checks):**", ""] + [f"- {n}" + (f" — `{d}`" if d else "") for n, d in g["checks"]] + [""]
        a = plan.get(g["kind"]) or (plan.get("zip") if g["kind"] == "archive" else None)
        if a and a.get("cmd"):
            out += ["**How it was attacked** (the library swaps `{PAYLOAD}` for the hostile values above):", "",
                    "```", " ".join(json.dumps(x) if " " in x else x for x in a["cmd"]), "```", ""]
        out += [f"**Fix:** {g['fix']}", ""]
    if r.get("invalid"):
        out += ["## Skipped (could not run, so NOT proof of safety)", ""] + [f"- {i}" for i in r["invalid"]] + [""]
    if fx:
        out += ["## Fix (seccheck --fix)", ""]
        if fx["status"].startswith("verified"):
            out += [f"**Status: VERIFIED** after {fx['tries']} attempt(s). Written to `{fx.get('out', '?')}`; your original was not changed.", "",
                    f"- Re-attack with the same plan, plus a fresh second plan: {fx['checks_passed']} checks passed, none failed.",
                    f"- Still works: {fx['strength']} normal-use test(s) give the same output as the original." if fx["strength"] else
                    "- Still works: NOT verified (no normal-use test produced output). Read the diff carefully.",
                    "- Verified means every hole seccheck found is closed. Holes it did not find are not fixed.", "",
                    "```diff", fx.get("diff", "").rstrip(), "```", ""]
        else:
            out += [f"**Status: REJECTED** after {fx['tries']} attempt(s). No fix was saved.", "", "Why:", ""] + [f"- {w}" for w in fx["reasons"]] + [""]
    if not fails:
        out += ["No checks failed. That means none of the attacks that ran found a hole, not that the code is proven safe.", ""]
    return "\n".join(out)
