"""Tests for the checker.

None of these need root or touch the real system. Each test builds a small fake
root directory under pytest's tmp_path, and the CLI tests use the two sample
directories next to this file.
"""

import json
from pathlib import Path

from checker.checks import ERROR, FAIL, PASS, SystemReader, run_checks
from checker.cli import main
from checker.report import build_report, format_text

SAMPLES = Path(__file__).parent / "sample_configs"

GOOD_META = {
    "/etc/passwd": {"mode": "0644", "owner": "root", "group": "root"},
    "/etc/shadow": {"mode": "0640", "owner": "root", "group": "shadow"},
    "/etc/ssh/sshd_config": {"mode": "0600", "owner": "root", "group": "root"},
}


# Small builders so each test only spells out the one value it cares about.

def login_defs(max_days="90", min_days="1", warn_age="7"):
    return (
        f"PASS_MAX_DAYS {max_days}\n"
        f"PASS_MIN_DAYS {min_days}\n"
        f"PASS_WARN_AGE {warn_age}\n"
    )


def sshd(root="no", empty="no", tries="4", x11="no"):
    return (
        f"PermitRootLogin {root}\n"
        f"PermitEmptyPasswords {empty}\n"
        f"MaxAuthTries {tries}\n"
        f"X11Forwarding {x11}\n"
    )


def build_root(tmp_path, files=None, meta=None, drop=()):
    """Write a fake root where every rule passes, then apply the overrides."""
    contents = {
        "etc/login.defs": login_defs(),
        "etc/security/pwquality.conf": "minlen = 14\n",
        "etc/ssh/sshd_config": sshd(),
        "etc/ufw/ufw.conf": "ENABLED=yes\n",
    }
    contents.update(files or {})
    for name in drop:
        contents.pop(name, None)
    for name, text in contents.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    metadata = dict(GOOD_META)
    metadata.update(meta or {})
    (tmp_path / "file_metadata.json").write_text(json.dumps(metadata))
    return tmp_path


def run_one(tmp_path, rule_id, files=None, meta=None):
    build_root(tmp_path, files, meta)
    return run_checks(SystemReader(tmp_path), {rule_id})[0]


def status(tmp_path, rule_id, files=None, meta=None):
    return run_one(tmp_path, rule_id, files, meta).status


def login(**kwargs):
    return {"etc/login.defs": login_defs(**kwargs)}


def ssh(**kwargs):
    return {"etc/ssh/sshd_config": sshd(**kwargs)}


def meta_entry(mode, owner="root", group="root"):
    return {"mode": mode, "owner": owner, "group": group}


# One test per rule, each with passing and failing values (boundaries included).

def test_pw1_password_max_days(tmp_path):
    assert status(tmp_path, "PW-1", login(max_days="90")) == PASS
    assert status(tmp_path, "PW-1", login(max_days="365")) == PASS
    assert status(tmp_path, "PW-1", login(max_days="366")) == FAIL
    assert status(tmp_path, "PW-1", login(max_days="99999")) == FAIL


def test_pw2_password_min_days(tmp_path):
    assert status(tmp_path, "PW-2", login(min_days="1")) == PASS
    assert status(tmp_path, "PW-2", login(min_days="30")) == PASS
    assert status(tmp_path, "PW-2", login(min_days="0")) == FAIL


def test_pw3_password_warn_age(tmp_path):
    assert status(tmp_path, "PW-3", login(warn_age="7")) == PASS
    assert status(tmp_path, "PW-3", login(warn_age="14")) == PASS
    assert status(tmp_path, "PW-3", login(warn_age="6")) == FAIL


def test_pw4_pwquality_minlen(tmp_path):
    files = {"etc/security/pwquality.conf": "minlen = 14\n"}
    assert status(tmp_path, "PW-4", files) == PASS
    files = {"etc/security/pwquality.conf": "minlen=20\n"}
    assert status(tmp_path, "PW-4", files) == PASS
    files = {"etc/security/pwquality.conf": "minlen = 8\n"}
    assert status(tmp_path, "PW-4", files) == FAIL


def test_ssh1_root_login(tmp_path):
    assert status(tmp_path, "SSH-1", ssh(root="no")) == PASS
    assert status(tmp_path, "SSH-1", ssh(root="yes")) == FAIL
    assert status(tmp_path, "SSH-1", ssh(root="prohibit-password")) == FAIL


def test_ssh2_empty_passwords(tmp_path):
    assert status(tmp_path, "SSH-2", ssh(empty="no")) == PASS
    assert status(tmp_path, "SSH-2", ssh(empty="yes")) == FAIL


def test_ssh3_max_auth_tries(tmp_path):
    assert status(tmp_path, "SSH-3", ssh(tries="3")) == PASS
    assert status(tmp_path, "SSH-3", ssh(tries="4")) == PASS
    assert status(tmp_path, "SSH-3", ssh(tries="5")) == FAIL
    assert status(tmp_path, "SSH-3", ssh(tries="6")) == FAIL


def test_ssh4_x11_forwarding(tmp_path):
    assert status(tmp_path, "SSH-4", ssh(x11="no")) == PASS
    assert status(tmp_path, "SSH-4", ssh(x11="yes")) == FAIL


def test_fw1_ufw_enabled(tmp_path):
    assert status(tmp_path, "FW-1", {"etc/ufw/ufw.conf": "ENABLED=yes\n"}) == PASS
    assert status(tmp_path, "FW-1", {"etc/ufw/ufw.conf": "ENABLED=YES\n"}) == PASS
    assert status(tmp_path, "FW-1", {"etc/ufw/ufw.conf": "ENABLED=no\n"}) == FAIL


def test_fp1_passwd_permissions(tmp_path):
    assert status(tmp_path, "FP-1") == PASS
    assert status(tmp_path, "FP-1", meta={"/etc/passwd": meta_entry("0664")}) == FAIL
    assert status(tmp_path, "FP-1", meta={"/etc/passwd": meta_entry("0644", owner="alice")}) == FAIL


def test_fp2_shadow_permissions(tmp_path):
    assert status(tmp_path, "FP-2") == PASS
    assert status(tmp_path, "FP-2", meta={"/etc/shadow": meta_entry("0600", group="shadow")}) == PASS
    assert status(tmp_path, "FP-2", meta={"/etc/shadow": meta_entry("0644", group="shadow")}) == FAIL
    assert status(tmp_path, "FP-2", meta={"/etc/shadow": meta_entry("0640", group="root")}) == FAIL


def test_fp3_sshd_config_permissions(tmp_path):
    assert status(tmp_path, "FP-3") == PASS
    assert status(tmp_path, "FP-3", meta={"/etc/ssh/sshd_config": meta_entry("0644")}) == FAIL


# Parsing and edge cases.

def test_missing_file_is_a_fail(tmp_path):
    build_root(tmp_path, drop=["etc/ufw/ufw.conf"])
    result = run_checks(SystemReader(tmp_path), {"FW-1"})[0]
    assert result.status == FAIL
    assert "not found" in result.detail


def test_commented_out_lines_are_ignored(tmp_path):
    files = {"etc/security/pwquality.conf": "# minlen = 14\n"}
    result = run_one(tmp_path, "PW-4", files)
    assert result.status == FAIL
    assert "not set" in result.detail


def test_sshd_first_occurrence_wins(tmp_path):
    good_first = {"etc/ssh/sshd_config": "PermitRootLogin no\nPermitRootLogin yes\n"}
    bad_first = {"etc/ssh/sshd_config": "PermitRootLogin yes\nPermitRootLogin no\n"}
    assert status(tmp_path, "SSH-1", good_first) == PASS
    assert status(tmp_path, "SSH-1", bad_first) == FAIL


def test_sshd_match_block_is_ignored(tmp_path):
    text = "PermitRootLogin no\nMatch User backup\n    PermitRootLogin yes\n"
    assert status(tmp_path, "SSH-1", {"etc/ssh/sshd_config": text}) == PASS


def test_sshd_default_is_used_when_keyword_is_missing(tmp_path):
    only_x11 = {"etc/ssh/sshd_config": "X11Forwarding no\n"}
    # the OpenSSH default for PermitEmptyPasswords is no, so this passes
    assert status(tmp_path, "SSH-2", only_x11) == PASS
    # the default for MaxAuthTries is 6 and the rule wants 4 or less
    assert status(tmp_path, "SSH-3", only_x11) == FAIL


def test_bad_numbers_fail(tmp_path):
    # -1 means "never expires", so it must not slip through an at-most check
    assert status(tmp_path, "PW-1", login(max_days="-1")) == FAIL
    result = run_one(tmp_path, "PW-3", login(warn_age="seven"))
    assert result.status == FAIL
    assert "not a whole number" in result.detail


def test_stricter_mode_passes_but_extra_bits_fail(tmp_path):
    assert status(tmp_path, "FP-1", meta={"/etc/passwd": meta_entry("0444")}) == PASS
    assert status(tmp_path, "FP-1", meta={"/etc/passwd": meta_entry("4644")}) == FAIL


def test_missing_metadata_file_is_an_error(tmp_path):
    build_root(tmp_path)
    (tmp_path / "file_metadata.json").unlink()
    result = run_checks(SystemReader(tmp_path), {"FP-1"})[0]
    assert result.status == ERROR
    assert "file_metadata.json" in result.detail


def test_unreadable_file_is_an_error(tmp_path, monkeypatch):
    build_root(tmp_path)

    def deny(self, path):
        raise PermissionError(path)

    monkeypatch.setattr(SystemReader, "read_text", deny)
    result = run_checks(SystemReader(tmp_path), {"SSH-1"})[0]
    assert result.status == ERROR
    assert "sudo" in result.detail


def test_live_reader_asks_the_os_for_mode(tmp_path):
    target = tmp_path / "somefile"
    target.write_text("x")
    target.chmod(0o640)
    reader = SystemReader(tmp_path)
    reader.live = True  # pretend this directory is the real machine
    mode, owner, group = reader.stat("/somefile")
    assert mode == 0o640
    assert owner and group  # names or numeric ids, depends on the machine


# Reports.

def test_json_report_has_the_expected_shape():
    results = run_checks(SystemReader(SAMPLES / "failing"))
    report = build_report(results, "somewhere")
    json.dumps(report)  # has to be serializable
    assert report["summary"] == {"total": 12, "passed": 0, "failed": 12, "errors": 0}
    assert len(report["results"]) == 12
    first = report["results"][0]
    assert {"id", "category", "title", "cis_ref", "status", "detail", "remediation"} <= set(first)
    assert all(item["remediation"] for item in report["results"])


def test_text_report_shows_fixes_only_for_failures():
    failing = run_checks(SystemReader(SAMPLES / "failing"))
    passing = run_checks(SystemReader(SAMPLES / "passing"))
    assert format_text(failing, "x").count("fix:") == 12
    assert "fix:" not in format_text(passing, "x")


def test_color_codes_only_appear_when_asked():
    results = run_checks(SystemReader(SAMPLES / "passing"))
    assert "\x1b[" in format_text(results, "x", use_color=True)
    assert "\x1b[" not in format_text(results, "x", use_color=False)


# CLI.

def test_cli_passing_sample_exits_0(capsys):
    code = main(["--target", str(SAMPLES / "passing"), "--no-color"])
    assert code == 0
    assert "12 checks: 12 passed, 0 failed, 0 errors" in capsys.readouterr().out


def test_cli_failing_sample_exits_1(capsys):
    code = main(["--target", str(SAMPLES / "failing"), "--no-color"])
    assert code == 1
    assert "0 passed, 12 failed" in capsys.readouterr().out


def test_cli_missing_target_exits_2(tmp_path, capsys):
    code = main(["--target", str(tmp_path / "does-not-exist")])
    assert code == 2
    assert "not a directory" in capsys.readouterr().err


def test_cli_writes_json_report(tmp_path):
    out = tmp_path / "report.json"
    code = main(["--target", str(SAMPLES / "failing"), "--json-out", str(out)])
    assert code == 1
    data = json.loads(out.read_text())
    assert data["summary"]["failed"] == 12
    assert data["target"] == str(SAMPLES / "failing")


def test_cli_rules_flag_runs_a_subset(capsys):
    code = main(["--target", str(SAMPLES / "passing"), "--rules", "ssh-1,fw-1", "--no-color"])
    out = capsys.readouterr().out
    assert code == 0
    assert "2 checks" in out
    assert "SSH-1" in out and "FW-1" in out
    assert "PW-1" not in out


def test_cli_unknown_rule_exits_2(capsys):
    code = main(["--target", str(SAMPLES / "passing"), "--rules", "NOPE-9"])
    assert code == 2
    assert "NOPE-9" in capsys.readouterr().err
