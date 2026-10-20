"""Rule definitions.

This file is only data: ids, thresholds, fix text and CIS references. The code
that does the checking is in checks.py.
"""

from dataclasses import dataclass
from typing import Any, Optional

BENCHMARK_NAME = "CIS Ubuntu Linux 22.04 LTS Benchmark"

# The control numbers below are what I wrote down from the layout of v1.0.0.
# I have not checked them against the PDF, and numbering shifts between
# versions, so a few of them are probably wrong. Only set this to True after
# going through all twelve by hand. The report prints a warning while it is False.
CIS_REFS_VERIFIED = False

LOGIN_DEFS = "/etc/login.defs"
PWQUALITY = "/etc/security/pwquality.conf"
SSHD_CONFIG = "/etc/ssh/sshd_config"
UFW_CONF = "/etc/ufw/ufw.conf"


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    title: str
    cis_ref: str
    source: str          # the file this rule looks at
    comparison: str      # "equals", "at_most", "at_least" or "perms"
    expected: Any        # threshold or wanted value, perms rules use (max_mode, owner, group)
    remediation: str
    setting: Optional[str] = None   # key inside the file, None for perms rules


RULES = (
    Rule(
        id="PW-1",
        category="Password policy",
        title="Password expiration is 365 days or less",
        cis_ref="5.5.1.1",
        source=LOGIN_DEFS,
        setting="PASS_MAX_DAYS",
        comparison="at_most",
        expected=365,
        remediation=(
            "Set PASS_MAX_DAYS 365 (or lower) in /etc/login.defs. Accounts that "
            "already exist keep their old value until you run chage --maxdays 365 <user>."
        ),
    ),
    Rule(
        id="PW-2",
        category="Password policy",
        title="Minimum days between password changes is 1 or more",
        cis_ref="5.5.1.2",
        source=LOGIN_DEFS,
        setting="PASS_MIN_DAYS",
        comparison="at_least",
        expected=1,
        remediation=(
            "Set PASS_MIN_DAYS 1 in /etc/login.defs, then run chage --mindays 1 <user> "
            "for accounts that already exist."
        ),
    ),
    Rule(
        id="PW-3",
        category="Password policy",
        title="Password expiration warning is 7 days or more",
        cis_ref="5.5.1.3",
        source=LOGIN_DEFS,
        setting="PASS_WARN_AGE",
        comparison="at_least",
        expected=7,
        remediation=(
            "Set PASS_WARN_AGE 7 in /etc/login.defs, then run chage --warndays 7 <user> "
            "for accounts that already exist."
        ),
    ),
    Rule(
        id="PW-4",
        category="Password policy",
        title="Minimum password length is 14 or more",
        cis_ref="5.4.1",
        source=PWQUALITY,
        setting="minlen",
        comparison="at_least",
        expected=14,
        remediation="Set minlen = 14 in /etc/security/pwquality.conf.",
    ),
    Rule(
        id="SSH-1",
        category="SSH hardening",
        title="SSH root login is disabled",
        cis_ref="5.2.10",
        source=SSHD_CONFIG,
        setting="PermitRootLogin",
        comparison="equals",
        expected="no",
        remediation="Set PermitRootLogin no in /etc/ssh/sshd_config, then run sudo systemctl restart ssh.",
    ),
    Rule(
        id="SSH-2",
        category="SSH hardening",
        title="SSH empty passwords are not allowed",
        cis_ref="5.2.11",
        source=SSHD_CONFIG,
        setting="PermitEmptyPasswords",
        comparison="equals",
        expected="no",
        remediation="Set PermitEmptyPasswords no in /etc/ssh/sshd_config, then run sudo systemctl restart ssh.",
    ),
    Rule(
        id="SSH-3",
        category="SSH hardening",
        title="SSH MaxAuthTries is 4 or less",
        cis_ref="5.2.7",
        source=SSHD_CONFIG,
        setting="MaxAuthTries",
        comparison="at_most",
        expected=4,
        remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config, then run sudo systemctl restart ssh.",
    ),
    Rule(
        id="SSH-4",
        category="SSH hardening",
        title="SSH X11 forwarding is disabled",
        cis_ref="5.2.6",
        source=SSHD_CONFIG,
        setting="X11Forwarding",
        comparison="equals",
        expected="no",
        remediation="Set X11Forwarding no in /etc/ssh/sshd_config, then run sudo systemctl restart ssh.",
    ),
    Rule(
        id="FW-1",
        category="Firewall",
        title="UFW is enabled in its config file",
        cis_ref="3.5.1.3",
        source=UFW_CONF,
        setting="ENABLED",
        comparison="equals",
        expected="yes",
        remediation=(
            "If you are connected over SSH, run sudo ufw allow ssh first or you can lock "
            "yourself out. Then run sudo ufw enable."
        ),
    ),
    Rule(
        id="FP-1",
        category="File permissions",
        title="/etc/passwd is 644 or stricter, owned by root:root",
        cis_ref="6.1.1",
        source="/etc/passwd",
        comparison="perms",
        expected=(0o644, "root", "root"),
        remediation="Run sudo chown root:root /etc/passwd and sudo chmod 644 /etc/passwd.",
    ),
    Rule(
        id="FP-2",
        category="File permissions",
        title="/etc/shadow is 640 or stricter, owned by root:shadow",
        cis_ref="6.1.5",
        source="/etc/shadow",
        comparison="perms",
        expected=(0o640, "root", "shadow"),
        remediation="Run sudo chown root:shadow /etc/shadow and sudo chmod 640 /etc/shadow.",
    ),
    Rule(
        id="FP-3",
        category="File permissions",
        title="/etc/ssh/sshd_config is 600 or stricter, owned by root:root",
        cis_ref="5.2.1",
        source=SSHD_CONFIG,
        comparison="perms",
        expected=(0o600, "root", "root"),
        remediation=(
            "Run sudo chown root:root /etc/ssh/sshd_config and "
            "sudo chmod 600 /etc/ssh/sshd_config."
        ),
    ),
)
