"""gitconfig-hijack-scanner: audit git config files for hijack-grade keys.

Git configuration is a persistence and execution vector that hides in
plain sight. An October 7, 2026 security report found git configuration
hijacking among eight vulnerabilities across seven AI coding agents
(dev.to) — coding agents that clone, init, or operate on repos inherit
whatever the repo's .git/config (or the user's global config) tells them
to do. Known-dangerous keys:

  core.hooksPath      -> attacker-controlled hook scripts run on git ops
  credential.helper    -> exfiltrate stored credentials on demand
  protocol.*.allow     -> re-enable dangerous transports (e.g. ext::)
  init.templateDir     -> poison every future repo you init/clone
  core.fsmonitor       -> arbitrary command execution on status
  include.path         -> pull in an attacker-written config file
  core.sshCommand      -> hijack SSH transport for every remote op
  url.<base>.insteadOf -> silently redirect fetches to attacker remotes

This tool deterministically audits .git/config and ~/.gitconfig for these
keys (severity per key, exact offending lines) — no heuristics, no ML, no
network. It flags facts, not vibes.

Python stdlib only. Deterministic: same config, same report.
"""

import json
import os
import re
import sys

# key pattern -> (severity, reason)
_DANGEROUS = (
    (re.compile(r"^core\.hookspath$", re.I), "CRITICAL",
     "core.hooksPath redirects git hooks to an attacker-controlled "
     "directory — hook scripts execute on clone/commit/merge operations"),
    (re.compile(r"^credential\.helper$", re.I), "HIGH",
     "credential.helper can shell out to an arbitrary command that "
     "receives your stored credentials on demand"),
    (re.compile(r"^protocol\.[^.]+\.allow$", re.I), "HIGH",
     "protocol.*.allow can re-enable dangerous transports such as "
     "ext::, which executes arbitrary commands"),
    (re.compile(r"^init\.templatedir$", re.I), "HIGH",
     "init.templateDir is copied into every repo you init or clone — "
     "a poisoned template backdoors all future repos"),
    (re.compile(r"^core\.fsmonitor$", re.I), "HIGH",
     "core.fsmonitor runs an arbitrary command on every git status — "
     "a classic persistence hook"),
    (re.compile(r"^include\.path$", re.I), "MEDIUM",
     "include.path pulls in another config file — verify the target "
     "file is one you trust"),
    (re.compile(r"^core\.sshcommand$", re.I), "MEDIUM",
     "core.sshCommand overrides the SSH transport for every remote "
     "operation — can redirect or proxy your git traffic"),
    (re.compile(r"^url\..*\.insteadof$", re.I), "MEDIUM",
     "url.<base>.insteadOf silently rewrites remote URLs — fetches and "
     "pushes can be redirected to an attacker's remote"),
    (re.compile(r"^core\.pager$", re.I), "LOW",
     "core.pager runs on log/diff output — a known (if noisy) command "
     "execution vector; keep it to less/more"),
    (re.compile(r"^core\.editor$", re.I), "INFO",
     "core.editor is noted for completeness — only risky if pointed at "
     "an unexpected binary"),
)

_SECTION_RE = re.compile(r"^\s*\[([^\]\"']+)(?:\s+\"([^\"]+)\")?\]\s*$")
_KV_RE = re.compile(r"^\s*([A-Za-z][\w.-]*)\s*=\s*(.*?)\s*$")


def _dangerous_match(key):
    """Return (severity, reason) for a key, or None. Deterministic."""
    kl = key.strip().lower()
    for pat, sev, reason in _DANGEROUS:
        if pat.match(kl):
            return sev, reason
    return None


def parse_gitconfig(text):
    """Parse git-config text into [(section, key, value, line_no)].

    Handles [section] and [section "subsection"] headers; keys are
    case-insensitive per git semantics. Continuation lines are joined.
    """
    entries = []
    section = ""
    pending = None  # (section, key, value_parts, line_no)
    for idx, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        m = _SECTION_RE.match(s)
        if m:
            if pending:
                entries.append(pending)
                pending = None
            base, sub = m.group(1).strip().lower(), m.group(2)
            section = base + ("." + sub.lower() if sub else "")
            continue
        kv = _KV_RE.match(s)
        if kv:
            if pending:
                entries.append(pending)
            pending = (section, kv.group(1).strip().lower(),
                       kv.group(2).strip(), idx)
        elif pending and (line.startswith((" ", "\t"))):
            # continuation of a multi-line value
            sec, key, val, lno = pending
            pending = (sec, key, val + "\n" + s, lno)
        # anything else is ignored (malformed lines are not our verdict)
    if pending:
        entries.append(pending)
    return entries


def scan_config(text, source="<input>"):
    """Scan git-config text. Returns [finding dicts]. Deterministic."""
    findings = []
    for section, key, value, lno in parse_gitconfig(text):
        full = ("%s.%s" % (section, key)).lstrip(".")
        hit = _dangerous_match(full)
        if hit:
            sev, reason = hit
            findings.append({
                "key": full,
                "value": value[:200],
                "severity": sev,
                "reason": reason,
                "file": source,
                "line": lno,
            })
    return findings


def scan_repo(repo_dir):
    """Scan <repo>/.git/config. Returns (findings, note)."""
    cfg = os.path.join(repo_dir, ".git", "config")
    if not os.path.isfile(cfg):
        return [], "no .git/config found at %s" % cfg
    with open(cfg, "r", encoding="utf-8", errors="replace") as fh:
        return scan_config(fh.read(), source=cfg), ""


def scan_global():
    """Scan ~/.gitconfig. Returns (findings, note)."""
    cfg = os.path.expanduser("~/.gitconfig")
    if not os.path.isfile(cfg):
        return [], "no ~/.gitconfig found"
    with open(cfg, "r", encoding="utf-8", errors="replace") as fh:
        return scan_config(fh.read(), source=cfg), ""


def render_markdown(findings):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    out = ["# gitconfig-hijack scan report", "",
           "%d finding(s)." % len(findings), ""]
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
        out.append("## [%s] %s" % (f["severity"], f["key"]))
        out.append("- value: `%s`" % f["value"])
        out.append("- location: %s:%d" % (f["file"], f["line"]))
        out.append("- %s" % f["reason"])
        out.append("")
    worst = min([order.get(f["severity"], 9) for f in findings], default=9)
    inv = {v: k for k, v in order.items()}
    out.append("**Worst finding:** %s" % (inv.get(worst, "NONE") if findings
                                          else "NONE — no hijack-grade keys"))
    return "\n".join(out)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Audit git config files for hijack-grade keys "
                    "(core.hooksPath, credential.helper, protocol.*.allow, ...).")
    ap.add_argument("target", nargs="?", default=".",
                    help="repo dir to scan (default: cwd)")
    ap.add_argument("--global", dest="do_global", action="store_true",
                    help="also scan ~/.gitconfig")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    findings, note = scan_repo(args.target)
    if note:
        print("note: " + note, file=sys.stderr)
    if args.do_global:
        gf, gnote = scan_global()
        findings.extend(gf)
        if gnote:
            print("note: " + gnote, file=sys.stderr)
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(render_markdown(findings))
    return 0


if __name__ == "__main__":
    sys.exit(main())
