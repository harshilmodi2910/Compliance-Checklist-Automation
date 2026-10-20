# compliance-checker

A small command line tool that reads a Linux system's config files and checks them against 12 rules based loosely on the CIS Ubuntu Linux 22.04 LTS Benchmark. Every rule gets a pass or fail, and failed rules come with a one-line fix. I built it on my own as a portfolio project to understand how benchmark checks work underneath.

## What this is not

This isn't CIS-CAT, and CIS hasn't certified or endorsed it. A clean run doesn't mean a system is CIS compliant, and it's no stand-in for a real compliance audit. The rules are my own simplified versions of a few CIS recommendations, so some thresholds or details could differ from the real ones. I also haven't compared its results against CIS-CAT or any other scanner.

## Why only 12 rules

The full benchmark has hundreds of recommendations. I kept 12 because I wanted to be able to explain every one of them, including why the number is what it is. I also wanted every rule to work from a config file or from file metadata, so the tool runs without root and can be demoed on a laptop. That ruled out anything that needs live state, like running services or loaded kernel modules.

CIS benchmarks split their recommendations into Level 1 and Level 2 profiles. Level 1 is meant to give a clear security benefit without getting in the way of normal use, and Level 2 is for environments that need more protection and can accept some loss of convenience.

## The rules

The CIS references are not verified yet. They come from my notes on the v1.0.0 layout, numbering moves around between benchmark versions, and I haven't checked each one against the PDF. Treat them as placeholders until I do. The report prints a warning about this, controlled by `CIS_REFS_VERIFIED` in `checker/rules.py`.

| ID | CIS ref (unverified) | What it checks | File |
|---|---|---|---|
| PW-1 | 5.5.1.1 | `PASS_MAX_DAYS` is 1 to 365 | `/etc/login.defs` |
| PW-2 | 5.5.1.2 | `PASS_MIN_DAYS` is 1 or more | `/etc/login.defs` |
| PW-3 | 5.5.1.3 | `PASS_WARN_AGE` is 7 or more | `/etc/login.defs` |
| PW-4 | 5.4.1 | `minlen` is 14 or more | `/etc/security/pwquality.conf` |
| SSH-1 | 5.2.10 | `PermitRootLogin no` | `/etc/ssh/sshd_config` |
| SSH-2 | 5.2.11 | `PermitEmptyPasswords no` | `/etc/ssh/sshd_config` |
| SSH-3 | 5.2.7 | `MaxAuthTries` is 4 or less | `/etc/ssh/sshd_config` |
| SSH-4 | 5.2.6 | `X11Forwarding no` | `/etc/ssh/sshd_config` |
| FW-1 | 3.5.1.3 | `ENABLED=yes` | `/etc/ufw/ufw.conf` |
| FP-1 | 6.1.1 | mode 644 or stricter, owner root:root | `/etc/passwd` |
| FP-2 | 6.1.5 | mode 640 or stricter, owner root:shadow | `/etc/shadow` |
| FP-3 | 5.2.1 | mode 600 or stricter, owner root:root | `/etc/ssh/sshd_config` |

"Or stricter" for the file rules means no permission bit is set that the limit doesn't have, so 600 passes a 640 rule and 664 doesn't.

## Running it

Needs Python 3.9 or newer. The tool itself uses only the standard library, and pytest is only for the tests. From the project folder:

```
python -m checker                                         # the machine you are on
python -m checker --target tests/sample_configs/failing   # a sample directory
python -m checker --json-out report.json                  # also save a JSON report
python -m checker --rules SSH-1,SSH-2 --no-color          # a subset, plain text
```

| Flag | What it does |
|---|---|
| `--target PATH` | Directory to treat as the filesystem root. Default is `/`. |
| `--json-out FILE` | Also write the full report to FILE as JSON. |
| `--rules ID[,ID...]` | Only run these rule ids. Not case sensitive. |
| `--no-color` | No color codes. Color is also off when output isn't a terminal or `NO_COLOR` is set. |

Exit codes are 0 when everything passes, 1 when any rule fails, and 2 for usage problems or when a check couldn't be done (an unreadable file, say). If both happen in one run, 2 wins, since an incomplete scan shouldn't look like a normal failure.

Output on the failing sample, trimmed:

```
[FAIL]  PW-1   5.5.1.1  Password expiration is 365 days or less
        PASS_MAX_DAYS is 99999, rule wants 365 or less
        fix: Set PASS_MAX_DAYS 365 (or lower) in /etc/login.defs. Accounts that already exist keep their old value until you run chage --maxdays 365 <user>.
...
[FAIL]  FP-2   6.1.5    /etc/shadow is 640 or stricter, owned by root:shadow
        mode 0644 allows more than 0640; group is root, rule wants shadow
        fix: Run sudo chown root:shadow /etc/shadow and sudo chmod 640 /etc/shadow.
...
12 checks: 0 passed, 12 failed, 0 errors
```

### Sample directories

`--target` is a root prefix. If you point it at `tests/sample_configs/passing`, the tool reads `etc/login.defs`, `etc/ssh/sshd_config` and so on from inside that folder.

Git doesn't keep file owners or modes, so the permission rules can't read them from a checked-out sample. When the target isn't `/`, they come from a `file_metadata.json` at the top of the target instead:

```json
{
  "/etc/shadow": {"mode": "0640", "owner": "root", "group": "shadow"}
}
```

If that file is missing, the three FP rules report ERROR. If it exists but doesn't list a path, that rule fails with a note saying so. With `--target /` the real modes and owners are read from the OS and the JSON file is never looked at.

### JSON report

The JSON has a `summary` with counts and a `results` list. Each result has `id`, `category`, `title`, `cis_ref`, `status`, `detail`, and `remediation` (only filled in for failures). It also records the target, a UTC timestamp, and whether the CIS references have been verified.

## A decision I went back and forth on

The question was what to do when `sshd_config` doesn't mention a keyword at all. My first version called that a fail, on the theory that a hardening rule should want the setting written down. That felt wrong for `PermitEmptyPasswords`, because sshd defaults to `no` there, so a stock config would fail a rule it actually satisfies. Then I looked at `sshd -T`, which prints the settings sshd really uses, defaults included. It would be the most accurate option, but as far as I can tell it needs root, and I wanted the tool to run without it.

I ended up with a small table of OpenSSH defaults in `checks.py`, and the report says when a value came from it. The downside is that the table is my own copy of those defaults, and a distro could change them without me noticing. I'm still not sure this beats just requiring explicit settings, which would at least be simpler to explain.

## Limitations

- **sshd_config is read as one file.** Ubuntu 22.04's stock file starts with an `Include` for `/etc/ssh/sshd_config.d/*.conf`. Since sshd keeps the first value it sees, a drop-in file can override what this tool reports. `Match` blocks are skipped too.
- **UFW is checked through its config file only.** `ENABLED=yes` in `ufw.conf` says nothing about whether ufw is running or what rules are loaded.
- **Password length only looks at `pwquality.conf`.** `minlen` can also be set in the PAM config under `/etc/pam.d`, and I don't read that, or `pwquality.conf.d`.
- **Password aging checks only see the defaults for new accounts.** Existing accounts keep their own settings in `/etc/shadow`, and the tool never reads that file's contents.
- **Running without root can produce ERROR results.** If `sshd_config` is 600 and owned by root, which is what FP-3 asks for, a normal user can't read it, so SSH-1 to SSH-4 report ERROR. Run with `sudo` to get real answers.
- **Repeated keys in `login.defs`:** the last one wins in my parser. I'm not sure that matches what the shadow tools do.
- **Comments:** only whole-line comments are handled, not trailing ones.
- **Linux only,** and only Ubuntu 22.04 was in mind.

## Tests

```
pip install -r requirements.txt
python -m pytest
```

There are 31 tests and none need root. Most build a small fake root directory in a temp folder, write the config files that test needs, and run the checks against it. Every rule has passing and failing cases, with boundary values like 365 and 366 where a number is involved. Other tests cover missing files, commented-out lines, sshd's first-value-wins behavior, `Match` blocks, the report formats, and the CLI exit codes. The one place I patch anything is file reading, to fake a permission error. The same workflow runs in GitHub Actions on Python 3.9 and 3.12.

## Layout

```
checker/
  rules.py    rule data: ids, thresholds, CIS refs, fix text
  checks.py   file reading, parsers, and the two kinds of check
  report.py   terminal text and JSON output
  cli.py      argument parsing and exit codes
tests/
  test_checks.py
  sample_configs/passing, sample_configs/failing
```

## License

MIT, see `LICENSE`.
