"""The checks themselves.

There are really only two kinds of rule: one that looks at a setting inside a
config file, and one that looks at a file's mode and owner. Each Rule in
rules.py says which kind it is through its comparison field, so I did not write
a separate function per rule.
"""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .rules import LOGIN_DEFS, RULES, SSHD_CONFIG, Rule

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"

METADATA_FILE = "file_metadata.json"

# What sshd falls back to when a keyword is not in sshd_config. These are the
# upstream OpenSSH defaults as far as I know. A distro can package different
# ones, so this table could be out of date for some systems.
SSHD_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "permitemptypasswords": "no",
    "maxauthtries": "6",
    "x11forwarding": "no",
}


class MetadataError(Exception):
    """file_metadata.json is missing or unreadable."""


class NotListed(Exception):
    """A path has no entry in file_metadata.json."""


@dataclass
class Result:
    rule: Rule
    status: str
    detail: str


class SystemReader:
    """Reads files from under a root directory.

    With root "/" it looks at the real machine and asks the OS for modes and
    owners. With any other root (a sample directory, say) git cannot store
    ownership, so modes and owners come from file_metadata.json in that root.
    """

    def __init__(self, root="/"):
        self.root = Path(root)
        self.live = self.root.resolve() == Path("/")
        self._metadata = None

    def path_for(self, path):
        return self.root / path.lstrip("/")

    def glob(self, pattern):
        """Expand a pattern like /etc/ssh/sshd_config.d/*.conf under the root.

        Returns paths in sorted order, which is the order sshd reads them as
        far as I can tell (it uses glob(3), which sorts).
        """
        found = sorted(self.root.glob(pattern.lstrip("/")))
        return ["/" + m.relative_to(self.root).as_posix() for m in found if m.is_file()]

    def read_text(self, path):
        return self.path_for(path).read_text(encoding="utf-8", errors="replace")

    def stat(self, path):
        """Return (mode, owner, group) for a path like /etc/passwd."""
        if self.live:
            return self._stat_live(path)
        return self._stat_from_metadata(path)

    def _stat_live(self, path):
        import grp
        import pwd

        info = os.stat(self.path_for(path))
        try:
            owner = pwd.getpwuid(info.st_uid).pw_name
        except KeyError:
            owner = str(info.st_uid)
        try:
            group = grp.getgrgid(info.st_gid).gr_name
        except KeyError:
            group = str(info.st_gid)
        return info.st_mode & 0o7777, owner, group

    def _load_metadata(self):
        meta_path = self.root / METADATA_FILE
        try:
            with open(meta_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            raise MetadataError(
                f"{METADATA_FILE} not found in {self.root}, so modes and owners are unknown"
            ) from None
        except (OSError, ValueError) as exc:
            raise MetadataError(f"could not read {METADATA_FILE}: {exc}") from exc
        if not isinstance(data, dict):
            raise MetadataError(f"{METADATA_FILE} should be a JSON object keyed by path")
        return data

    def _stat_from_metadata(self, path):
        if self._metadata is None:
            self._metadata = self._load_metadata()
        entry = self._metadata.get(path)
        if entry is None:
            raise NotListed(f"{path} is not listed in {METADATA_FILE}")
        try:
            return int(str(entry["mode"]), 8), entry["owner"], entry["group"]
        except (KeyError, TypeError, ValueError):
            raise MetadataError(f"bad entry for {path} in {METADATA_FILE}") from None


# Parsers. They only handle whole-line comments. I did not try to handle
# trailing comments because I am not sure every one of these programs does.

def _meaningful_lines(text):
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            yield line


def parse_login_defs(text):
    """KEY value, separated by whitespace. If a key repeats the last one wins.

    I am not certain which duplicate the shadow tools really use. It does not
    matter for a normal file, only for one that sets the same key twice.
    """
    values = {}
    for line in _meaningful_lines(text):
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0]] = parts[1].strip()
    return values


def parse_key_value(text):
    """key = value, used for pwquality.conf and ufw.conf. Last one wins."""
    values = {}
    for line in _meaningful_lines(text):
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


# How deep Include lines can nest before I stop following them. This is only
# here so a file that includes itself cannot loop forever.
MAX_INCLUDE_DEPTH = 5
SSH_DIR = "/etc/ssh"


class _SshdParser:
    """Collects global sshd settings, following Include lines where they appear."""

    def __init__(self, reader):
        self.reader = reader
        self.values = {}
        self.stopped = False  # set at the first Match line

    def feed(self, text, depth=0):
        for line in _meaningful_lines(text):
            if self.stopped:
                return
            parts = re.split(r"[\s=]+", line, maxsplit=1)
            keyword = parts[0].lower()
            if keyword == "match":
                # Everything after a Match line belongs to a Match block, which
                # runs until the next Match or the end of the file. So I treat
                # it as the end of the global settings. I do this even when the
                # Match line is inside an included file, and I am not sure sshd
                # scopes it the same way there.
                self.stopped = True
                return
            if len(parts) != 2:
                continue
            if keyword == "include":
                self._include(parts[1], depth)
            elif keyword not in self.values:
                self.values[keyword] = parts[1].strip().strip('"')

    def _include(self, argument, depth):
        if self.reader is None or depth >= MAX_INCLUDE_DEPTH:
            return
        for pattern in argument.split():
            pattern = pattern.strip('"')
            if not pattern.startswith("/"):
                # relative patterns are taken from /etc/ssh
                pattern = f"{SSH_DIR}/{pattern}"
            for path in self.reader.glob(pattern):
                self.feed(self.reader.read_text(path), depth + 1)
                if self.stopped:
                    return


def parse_sshd_config(text, reader=None):
    """Keyword value, or Keyword=value. Keywords are case-insensitive.

    sshd keeps the FIRST value it sees for a keyword, so that is what I keep.
    An Include line is read right where it appears, so a drop-in file listed
    at the top of the main file wins over settings further down. Without a
    reader, Include lines are ignored.
    """
    parser = _SshdParser(reader)
    parser.feed(text)
    return parser.values


# The two kinds of check.

def _describe(rule):
    if rule.comparison == "at_most":
        return f"{rule.expected} or less"
    if rule.comparison == "at_least":
        return f"{rule.expected} or more"
    return str(rule.expected)


def _judge(rule, raw, note=""):
    if rule.comparison == "equals":
        ok = raw.lower() == str(rule.expected).lower()
    else:
        try:
            number = int(raw)
        except ValueError:
            return Result(rule, FAIL, f"{rule.setting} is {raw!r}, which is not a whole number")
        if rule.comparison == "at_most":
            # The lower bound is there because PASS_MAX_DAYS -1 means "never
            # expires" and would otherwise pass an at-most-365 comparison.
            ok = 1 <= number <= rule.expected
        else:
            ok = number >= rule.expected
    detail = f"{rule.setting} is {raw}{note}"
    if not ok:
        detail += f", rule wants {_describe(rule)}"
    return Result(rule, PASS if ok else FAIL, detail)


def check_setting(reader, rule):
    text = reader.read_text(rule.source)
    if rule.source == SSHD_CONFIG:
        key = rule.setting.lower()
        raw = parse_sshd_config(text, reader).get(key)
        note = ""
        if raw is None:
            raw = SSHD_DEFAULTS.get(key)
            note = " (not set in the file, OpenSSH default)"
        if raw is None:
            return Result(rule, FAIL, f"{rule.setting} is not set in {rule.source}")
        return _judge(rule, raw, note)

    if rule.source == LOGIN_DEFS:
        values = parse_login_defs(text)
    else:
        values = parse_key_value(text)
    raw = values.get(rule.setting)
    if raw is None:
        return Result(rule, FAIL, f"{rule.setting} is not set in {rule.source}")
    return _judge(rule, raw)


def check_permissions(reader, rule):
    max_mode, want_owner, want_group = rule.expected
    mode, owner, group = reader.stat(rule.source)
    problems = []
    if mode & ~max_mode:
        # Any bit set that the limit does not have means "looser than allowed".
        problems.append(f"mode {mode:04o} allows more than {max_mode:04o}")
    if owner != want_owner:
        problems.append(f"owner is {owner}, rule wants {want_owner}")
    if group != want_group:
        problems.append(f"group is {group}, rule wants {want_group}")
    if problems:
        return Result(rule, FAIL, "; ".join(problems))
    return Result(rule, PASS, f"{rule.source} is {mode:04o} {owner}:{group}")


def _run_one(reader, rule):
    try:
        if rule.comparison == "perms":
            return check_permissions(reader, rule)
        return check_setting(reader, rule)
    except NotListed as exc:
        return Result(rule, FAIL, str(exc))
    except FileNotFoundError:
        return Result(rule, FAIL, f"{rule.source} was not found")
    except PermissionError as exc:
        name =getattr(exc, "filename", None) or rule.source
        return Result(rule, ERROR, f"not allowed to read {name}, try running with sudo")
    except (MetadataError, OSError) as exc:
        return Result(rule, ERROR, str(exc))


def run_checks(reader, rule_ids=None):
    """Run every rule, or only the ids in rule_ids, in the order rules.py lists them."""
    selected = [rule for rule in RULES if rule_ids is None or rule.id in rule_ids]
    return [_run_one(reader, rule) for rule in selected]
