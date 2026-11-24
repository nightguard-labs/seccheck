"""seccheck v1.1: fix + verify (11/23).

After a FLAG, the checker model writes a fixed copy of the code. seccheck only shows the fix if it passes two tests:
  1. RE-ATTACK: the same attack plan runs against the fixed copy; every hole that got through must now be blocked,
     with no new failures and no extra skips. Then a FRESH plan attacks it too (a plan only tests what it thought of).
  2. STILL WORKS: normal-use commands (written from the task BEFORE any fix exists, answers recorded on the original)
     must give the same output on the fixed copy. A fix that deletes features fails here.
The original code is never changed. The fixed copy is written out only when both tests pass.
"""
import difflib, json, re, shutil, sys, tempfile
from pathlib import Path
import core, report

FIX_PROMPT = """You are fixing security holes in a small program that another AI wrote.
Keep everything else exactly the same: same commands, same arguments, same output for normal use.

TASK the program must do:
{task}

CODE:
{code}

SECURITY HOLES FOUND (these attacks got through):
{findings}

Reply with the COMPLETE fixed version of each file you change, in exactly this format, and nothing else:
=== FILE: name.py ===
```python
...whole file...
```
Change only what is needed to close the holes."""

USAGE_PROMPT = """Write NORMAL-USE test commands for this program (not attacks), based on the task.
They will be run on the program to record how it behaves when used normally.

TASK:
{task}

CODE:
{code}

Reply with ONLY a JSON object:
{{"setup": [["python3", "prog.py", "..."], ...], "checks": [["python3", "prog.py", "..."], ...]}}
- setup: 2-4 commands that store ordinary data (if the program stores anything); otherwise [].
- checks: 2-4 commands whose printed output shows the program works (find what was stored, show a real file).
- Use only inputs an honest, normal user would give, following every rule in the TASK (for example, if the task says
  users only go to pages on our own site, use paths like /home, never outside sites). Don't copy odd things the code allows.
- Use {{DIR}} for a writable folder (e.g. a database path {{DIR}}/data.db). Only use files that really exist in CODE.
- Every command is a list of strings."""


def files_of(code_dir):
    return {str(f.relative_to(code_dir)) for f in Path(code_dir).rglob("*") if f.is_file()}


def parse_files(reply, allowed):
    """Pull '=== FILE: x ===' blocks out of the reply. Only files that already exist may be replaced (no new paths,
    no '..', no absolute names), so a model's reply can never write outside the copy."""
    out = {}
    for name, body in re.findall(r"===\s*FILE:\s*(\S+)\s*===\s*```[\w+-]*\n(.*?)```", reply, re.S):
        name = name.strip().lstrip("./")
        if name in allowed and ".." not in Path(name).parts and not Path(name).is_absolute():
            out[name] = body if body.endswith("\n") else body + "\n"
    return out


def usage_plan(model, task, code):
    """Ask for normal-use commands; keep only well-formed ones."""
    for _ in range(2):
        j = core.parse_plan(core.ask(model, USAGE_PROMPT.format(task=task, code=code), 800))
        if not isinstance(j, dict): continue
        ok = lambda c: isinstance(c, list) and c and all(isinstance(x, str) for x in c)
        setup = [c for c in (j.get("setup") or []) if ok(c)]
        checks = [c for c in (j.get("checks") or []) if ok(c)]
        if checks: return {"attacks": [{"kind": "usage", "setup": setup, "cmd": c} for c in checks]}
    return {"attacks": []}


def findings_text(r):
    lines = []
    for n, ok, d in r["checks"]:
        if ok: continue
        _, title, cwe, _, fix = report._rule(n)
        lines.append(f"- {title} {cwe}: check \"{n}\" failed" + (f" [{d}]" if d else "") + f"\n  standard fix: {fix}")
    return "\n".join(lines)


def judge(r0, r1, base, after):
    """Return (verified, reasons, behavior_strength)."""
    why = []
    f0 = {n for n, ok, _ in r0["checks"] if not ok}
    res1 = {n: ok for n, ok, _ in r1.get("checks", [])}
    still = [n for n in f0 if res1.get(n) is not True]
    new = [n for n, ok in res1.items() if not ok and n not in f0]
    if r1.get("verdict") == "no-verdict": why.append("re-attack could not run: " + str(r1.get("why")))
    if still: why.append("still open: " + "; ".join(still))
    if new: why.append("new failures: " + "; ".join(new))
    if len(r1.get("invalid", [])) > len(r0.get("invalid", [])): why.append("more attacks were skipped on the fix than on the original")
    if base is None or after is None: why.append("still-works check could not run")
    else:   # compare only inputs where the ORIGINAL worked; a fix may handle errors better (crash -> clear message)
        if len(base) != len(after): why.append("behavior changed: different number of results")
        diffs = [f"{a[1]} input {a[2]!r}: printed {a[4][:60]!r}, now {b[3]}/{b[4][:60]!r}" for a, b in zip(base, after) if a[3] is True and a != b]
        if diffs: why.append("behavior changed: " + "; ".join(diffs[:3]))
    strength = sum(1 for row in (base or []) if row[1] == "usage" and row[3] is True and row[4].strip())
    return (not why), why, strength


def run(task_file, code_dir, model, r0, tries=2, log=print):
    task, code = Path(task_file).read_text(), core.code_text(code_dir)
    allowed = files_of(code_dir)
    log("fix: writing normal-use tests from the task (before any fix exists)")
    up = usage_plan(model, task, code)
    check_plan = {"attacks": (r0["plan"].get("attacks", []) if isinstance(r0.get("plan"), dict) else []) + up["attacks"]}
    base = core.smoke(check_plan, code_dir)
    feedback, result = "", {"status": "failed", "reasons": ["model wrote no usable fix"], "files": {}, "tries": 0}
    for t in range(1, tries + 1):
        log(f"fix: attempt {t}: asking {model} for a fix")
        reply = core.ask(model, FIX_PROMPT.format(task=task, code=code, findings=findings_text(r0)) + feedback, 4000)
        files = parse_files(reply, allowed)
        if not files:
            feedback = "\n\nYour last reply had no '=== FILE: name ===' block for an existing file. Use the exact format."
            continue
        tmp = Path(tempfile.mkdtemp(prefix="seccheck-fix-")); fixed = tmp / "code"
        shutil.copytree(code_dir, fixed)
        for n, body in files.items(): (fixed / n).write_text(body)
        log("fix: re-attacking the fixed copy with the same plan")
        r1 = core.attack(task_file, str(fixed), model, plan=r0["plan"])
        after = core.smoke(check_plan, str(fixed))
        ok, why, strength = judge(r0, r1, base, after)
        r2 = None
        if ok:   # 11/23: a plan only tests what it thought of. Attack the fix again with a FRESH plan before trusting it.
            log("fix: second opinion: a fresh attack plan against the fixed copy")
            r2 = core.attack(task_file, str(fixed), model)
            f2 = [n for n, k, _ in r2.get("checks", []) if not k]
            if f2: ok = False; why.append("a fresh attack plan found: " + "; ".join(f2)); r1 = {**r1, "checks": r1["checks"] + r2["checks"]}
        diff = "".join("".join(difflib.unified_diff((Path(code_dir) / n).read_text().splitlines(True), body.splitlines(True), f"a/{n}", f"b/{n}")) for n, body in files.items())
        result = {"status": "verified" if ok else "failed", "reasons": why, "files": files, "diff": diff, "tries": t,
                  "strength": strength, "usage_cmds": len(up["attacks"]), "recheck": r1, "second": r2, "dir": str(fixed),
                  "checks_passed": len(r1.get("checks", [])) + len((r2 or {}).get("checks", []))}
        if ok:
            if strength == 0: result["status"] = "verified-attacks-only"
            return result
        hints = sorted({report._rule(n)[4] for n, ok in ((c[0], c[1]) for c in r1.get("checks", [])) if not ok})
        feedback = ("\n\nYour previous fix was tested by re-running the attacks, and REJECTED:\n- " + "\n- ".join(why) +
                    ("\nThe standard fix for what is still open:\n- " + "\n- ".join(hints) if hints else "") +
                    "\nThe test result is final; don't argue with it in comments. Write a corrected fix. Keep normal behavior identical.")
        shutil.rmtree(tmp, ignore_errors=True)
    return result
