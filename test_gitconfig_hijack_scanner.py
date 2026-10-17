"""Tests for gitconfig_hijack_scanner. Deterministic, no network, no fs writes."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gitconfig_hijack_scanner import parse_gitconfig, scan_config

PASS, FAIL = [], []


def check(name, fn):
    try:
        fn()
        PASS.append(name)
        print("PASS  " + name)
    except Exception as e:
        FAIL.append((name, repr(e)))
        print("FAIL  %s: %r" % (name, e))


def t_hooks_path_is_critical():
    f = scan_config("[core]\n\thooksPath = /tmp/evil-hooks\n")
    assert len(f) == 1 and f[0]["severity"] == "CRITICAL", f
    assert f[0]["key"] == "core.hookspath"


def t_credential_helper_is_high():
    f = scan_config('[credential]\n\thelper = !/tmp/steal.sh\n')
    assert f[0]["severity"] == "HIGH", f


def t_protocol_allow_is_high():
    f = scan_config('[protocol "ext"]\n\tallow = always\n')
    assert f[0]["severity"] == "HIGH" and "ext" in f[0]["key"], f


def t_init_template_is_high():
    f = scan_config("[init]\n\ttemplateDir = /tmp/tpl\n")
    assert f[0]["severity"] == "HIGH", f


def t_fsmonitor_is_high():
    f = scan_config("[core]\n\tfsmonitor = /tmp/watcher\n")
    assert f[0]["severity"] == "HIGH", f


def t_include_path_is_medium():
    f = scan_config('[include]\n\tpath = /tmp/extra.inc\n')
    assert f[0]["severity"] == "MEDIUM", f


def t_instead_of_is_medium():
    f = scan_config('[url "https://evil.example/"]\n\tinsteadOf = https://github.com/\n')
    assert f[0]["severity"] == "MEDIUM" and "insteadof" in f[0]["key"], f


def t_case_insensitive():
    f = scan_config("[CORE]\n\tHooksPath = /tmp/x\n")
    assert f and f[0]["severity"] == "CRITICAL", f


def t_clean_config_no_findings():
    f = scan_config("[user]\n\tname = Jane\n\temail = jane@example.com\n"
                    "[core]\n\trepositoryformatversion = 0\n")
    assert f == [], f


def t_line_numbers_correct():
    f = scan_config("[user]\n\tname = x\n[core]\n\thooksPath = /tmp/y\n")
    assert f[0]["line"] == 4, f


def t_parse_sections():
    e = parse_gitconfig('[core]\n\ta = 1\n[remote "origin"]\n\turl = x\n')
    assert e[0][0] == "core" and e[1][0] == "remote.origin", e


def t_deterministic():
    text = "[core]\n\thooksPath = /tmp/a\n"
    assert scan_config(text) == scan_config(text)


def t_empty_input():
    assert scan_config("") == []


def t_pager_is_low():
    f = scan_config("[core]\n\tpager = /tmp/pager.sh\n")
    assert f[0]["severity"] == "LOW", f


def t_multiple_findings_sorted():
    from gitconfig_hijack_scanner import render_markdown
    f = scan_config("[core]\n\tpager = x\n\thooksPath = y\n")
    md = render_markdown(f)
    assert md.index("CRITICAL") < md.index("LOW"), md


def test_all_checks():
    """pytest entry point: runs every t_* check."""
    for name, fn in sorted([(k, v) for k, v in globals().items()
                            if k.startswith("t_")]):
        fn()


if __name__ == "__main__":
    for name, fn in sorted([(k, v) for k, v in globals().items()
                            if k.startswith("t_")]):
        check(name, fn)
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    sys.exit(1 if FAIL else 0)
