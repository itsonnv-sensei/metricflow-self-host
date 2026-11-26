"""Secret scan of what is about to be committed: pre-commit hook ``secret-scan``, step 2 of the CI job verify.

The secret scanner of the company flags anything shaped like a credential, the fake values of the tests included,
so the repository holds none. A line fails on:
  key      a key named like a credential (password, pass, pwd, passphrase, secret, token, credential, api key,
           access key, private key, mk, mat_khau, "mật khẩu", in any spelling: CH_PASSWORD, apiKey, Job-Token) given
           a value written in the file, also as the next argument or item (setenv, environ[...]). A reference
           passes: a variable or a call in Python and SQL, $VAR, ${VAR}, {{ env_var('VAR') }}, <placeholder>,
           a path, an empty, boolean or masked value. Not checked in the translations i18n/locales/*.json: their
           values are sentences of the UI
  flag     a password on a command line: -p glued to a value (the mysql way), the long password or token options
           followed by a value, sshpass with -p, curl -u followed by user:password, an Authorization header
  url      user:password@ in an address
  token    the shape of a known token or key: GitLab, GitHub, Slack, AWS, Google, OpenAI / Anthropic, JWT, Fernet,
           bcrypt, Teams / Power Automate webhook addresses (they carry their signature), private key blocks
  network  a private IPv4 address (10/8, 172.16/12, 192.168/16): hosts live in .env
  hex      32 hexadecimal characters or more, the shape of the passwords of the warehouse (lock files, full
           sha256: / sha384: / sha512: digests and the operation ids graphql-codegen writes in *.types.ts and
           client.json excepted)
  file     a file or folder named like a credential or a key store (password, credential, matkhau, .pem, .key, .p12,
           id_rsa, .pgpass, .netrc, .htpasswd...), an .env file, a binary file the scan cannot read
There is no marker to skip a line: rewrite it (a variable, a value made at run time), or change this script through
a merge request. Messages are in Vietnamese, like the CI logs. Standard library only: it runs before any install.

Usage: scan_secrets.py FILE...   the files pre-commit passes: the lines a file adds or changes against HEAD, all of
                                 a file HEAD does not have (a fork changes a few lines of many upstream files)
       scan_secrets.py --all     every line of every file git tracks (CI)
"""

from __future__ import annotations

import io
import itertools
import re
import subprocess
import sys
import tokenize
import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# words of a key that hold a credential; a key is split on _ - . spaces and camelCase first
KEY_WORDS = frozenset(
    {
        "password",
        "passwords",
        "passwd",
        "pass",
        "passphrase",
        "pwd",
        "secret",
        "secrets",
        "token",
        "tokens",
        "credential",
        "credentials",
        "apikey",
        "accesskey",
        "privatekey",
        "secretkey",
        "mk",
        "matkhau",
    }
)
# words also found inside a longer one: PGPASSWORD, NOPASSWD, client_secrets
INNER_WORDS = ("password", "passwd", "passphrase", "credential", "secret", "apikey", "matkhau")
KEY_PAIRS = frozenset({("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"), ("mat", "khau")})

# key, operator, then the value (read in a lookahead, so the next key of the same line is found too)
ASSIGN = re.compile(
    r"""(?P<key>"[^"\n]{1,80}"|'[^'\n]{1,80}'|`[^`\n]{1,80}`|[A-Za-z_][\w.\-]{0,80})"""
    r"""(?P<before>\s*)(?P<op>:=|=>|==|=|:)(?![=:/])(?P<after>\s*)(?=(?P<value>[^\n]*))"""
)
# a credential key and its value as two arguments or an item: setenv("CH_PASSWORD", "..."), environ["..."] = "..."
PAIR = re.compile(r"""(?P<key>"[^"\n]{1,80}"|'[^'\n]{1,80}')\s*(?P<op>\]\s*=|,)\s*(?=(?P<value>[^\n]*))""")
QUOTED = re.compile(r"""(?:[rRbBuUfF]{1,2})?(["'`])(.*?)\1""")
BARE = re.compile(r"""(?![\[({])[^\s,;)\]}"'`#]+""")  # a list, a tuple or a mapping is not one value
REFERENCE = re.compile(r"^(?:\$|\{|<|%\(|#\{|@|/|\./|\.\./|~/)")
CODE_REFERENCE = re.compile(r"^(?:[A-Z][A-Z0-9_]*|[A-Za-z_]\w*(?:\.\w+)+|[A-Za-z_][\w.]*[(\[])")
MASKED = re.compile(r"^[*xX•.…_\- ]*$")
NOT_SECRET = frozenset({"true", "false", "yes", "no", "on", "off", "null", "none", "nil", "~"})

FLAGS = (
    re.compile(r"""(?:^|[\s"'\[(,=])-p(?P<value>[^\s"'=,;)\]\\]+)"""),
    re.compile(r"""(?i)--(?:password|passwd|pass|pwd|token|secret|api-?key|access-?key)(?:=|\s+)(?P<value>[^\s"']+)"""),
    re.compile(r"(?i)\bsshpass\s+-p\s*(?P<value>\S+)"),
    re.compile(r"""(?i)(?:\s-u|--user)\s+[^\s:"']+:(?P<value>[^\s@"']+)"""),
    re.compile(r"""(?i)\bauthorization["']?\s*[:=]\s*["']?(?:basic|bearer|token)\s+(?P<value>[\w.~+/=-]{8,})"""),
)
URL_PASSWORD = re.compile(r"""(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@"'<>]+:(?P<value>[^\s@/"'<>]+)@""")
TOKENS = (
    ("token GitLab", re.compile(r"\b(?:glpat|glrt|gldt|glft|glptt|glcbt|gloas|glimt|glagent|glsoat)-[\w-]{20,}")),
    ("token đăng ký runner GitLab", re.compile(r"\bGR1348941[\w-]{20,}")),
    ("token GitHub", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_\w{22,})")),
    ("token Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("khoá AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("khoá API Google", re.compile(r"\bAIza[\w-]{35}")),
    ("khoá API OpenAI / Anthropic", re.compile(r"\bsk-(?:ant-|proj-)?[\w-]{20,}")),
    ("JWT", re.compile(r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}")),
    ("chuỗi mã hoá Fernet", re.compile(r"\bgAAAAAB[\w-]{40,}")),
    ("mã băm bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    (
        "địa chỉ webhook Teams / Power Automate",
        re.compile(
            r"""(?i)https?://[^\s"'<>]*(?:webhook\.office\.com|logic\.azure\.com|powerplatform\.com"""
            r"""|powerautomate\.com|flow\.microsoft\.com)[^\s"'<>]*"""
        ),
    ),
    ("chữ ký sig= của webhook", re.compile(r"[?&]sig=[\w%-]{16,}")),
    ("khoá riêng (private key)", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY")),
)
PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")
HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])")
# a content digest of full length (pip --hash=sha256:..., a Docker image id) names a file, it is not a secret
DIGEST = re.compile(r"\bsha(?:256:[0-9a-f]{64}|384:[0-9a-f]{96}|512:[0-9a-f]{128})(?![0-9A-Za-z])")
# the sha256 of a GraphQL operation on a whole line written by graphql-codegen: a TS constant or a client.json entry
OPERATION_ID = re.compile(r"^(?:export const \w+Version = '[0-9a-f]{64}';|\s*\"\w+\": \"[0-9a-f]{64}\",?)$")
OPERATION_ID_FILES = re.compile(r"(?:^|/)(?:client\.json|[^/]+\.types\.ts)$")

LOCK_FILES = frozenset({"uv.lock", "poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock"})
LOCALE = re.compile(r"(?:^|/)i18n/locales/[^/]+\.json$")  # English text -> translation: no credential keys
HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@", re.MULTILINE)
SECRET_NAME = re.compile(
    r"password|passwd|credential|mat[_-]?khau|htpasswd|pgpass|netrc|pypirc|kubeconfig|keystore|keychain"
    r"|^id_(?:rsa|dsa|ecdsa|ed25519)(?!.*\.pub$)"
)
SECRET_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx", ".ppk", ".ovpn", ".gpg", ".asc"})
ENV_FILE = re.compile(r"^\.env(?:\..+)?$")

PYTHON = frozenset({".py", ".pyi"})
CODE = frozenset({".sql", ".js", ".ts", ".go", ".java", ".scala"})  # bare values are references to code
CONFIG = frozenset(
    {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".sh", ".bash", ".zsh", ".json"}
    | {".service", ".timer", ".mk", ".example"}
)
CONFIG_NAMES = frozenset({"makefile", "dockerfile", "sudoers", "containerfile", "caddyfile", "jenkinsfile"})


@dataclass(frozen=True)
class Finding:
    path: str
    line: int  # 0: the file itself
    rule: str
    message: str
    excerpt: str = ""

    def __str__(self) -> str:
        where = f"{self.path}:{self.line}" if self.line else self.path
        return f"{where}: [{self.rule}] {self.message}" + (f"\n    {self.excerpt}" if self.excerpt else "")


def plain(text: str) -> str:
    """Lower ASCII form for matching: no Vietnamese accents, "mật khẩu" as one word."""
    text = unicodedata.normalize("NFD", text.replace("đ", "d").replace("Đ", "D"))
    text = "".join(char for char in text if not unicodedata.combining(char))
    return re.sub(r"(?i)\bmat[ _-]?khau\b", "matkhau", text)


def secret_key(key: str) -> bool:
    if "/" in key:
        return False  # a path (a file named secrets.py), not a key
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", plain(key.strip("\"'`")))
    parts = [part for part in re.split(r"[^a-z0-9]+", words.lower()) if part]
    if any(part in KEY_WORDS or any(word in part for word in INNER_WORDS) for part in parts):
        return True
    return any(pair in KEY_PAIRS for pair in itertools.pairwise(parts))


def kind_of(path: str) -> str:
    """python, code (bare values are references), config (bare values are literals) or text."""
    name = PurePosixPath(path).name.lower()
    suffix = PurePosixPath(name).suffix
    if suffix in PYTHON:
        return "python"
    if suffix in CODE:
        return "code"
    if suffix in CONFIG or name in CONFIG_NAMES or ENV_FILE.match(name):
        return "config"
    return "text"


def written_value(value: str) -> tuple[str, bool] | None:
    """(text, quoted) of the value after the operator, None when there is none."""
    quoted = QUOTED.match(value)
    if quoted:
        return quoted.group(2), True
    bare = BARE.match(value)
    return (bare.group(0), False) if bare else None


def looks_secret(text: str) -> bool:
    """A value with a digit, 4 characters or more: a password rather than a word or a name."""
    return len(text) >= 4 and any(char.isdigit() for char in text)


def literal_secret(kind: str, text: str, quoted: bool, tight: bool) -> bool:
    """True when the value written for a credential key is a literal, not a reference."""
    text = text.strip()
    if not text or MASKED.match(text) or REFERENCE.match(text) or text.lower() in NOT_SECRET:
        return False
    if quoted:
        return True
    if kind == "config":
        return True
    if kind in ("python", "code") or CODE_REFERENCE.match(text):
        return False
    # text: a value glued to "=", or one that looks like a password
    return tight or looks_secret(text)


def masked(line: str, value: str) -> str:
    line = line.strip()
    if value:
        line = line.replace(value, "***")
    return line if len(line) <= 160 else line[:159] + "…"


def key_finding(path: str, number: int, line: str, key: str, value: str) -> Finding:
    key = key.strip("\"'`")
    message = f"khoá '{key}' mang giá trị viết sẵn: thay bằng biến môi trường hoặc giá trị sinh lúc chạy"
    return Finding(path, number, "key", message, masked(line, value))


def key_findings(path: str, number: int, line: str, kind: str) -> Iterator[Finding]:
    line = plain(line)
    for match in PAIR.finditer(line):
        value = written_value(match.group("value"))
        if not secret_key(match.group("key")) or value is None or not value[1]:
            continue  # a pair is a literal only when the value is quoted: a list of key names is not
        text = value[0].strip()
        if literal_secret(kind, text, True, False) and (match.group("op") != "," or looks_secret(text)):
            yield key_finding(path, number, line, match.group("key"), text)
    for match in ASSIGN.finditer(line):
        if not secret_key(match.group("key")):
            continue
        value = written_value(match.group("value"))
        if value is None:
            continue
        tight = match.group("op") == "=" and not match.group("before") and not match.group("after")
        if literal_secret(kind, value[0], value[1], tight):
            yield key_finding(path, number, line, match.group("key"), value[0])


def pattern_findings(path: str, number: int, line: str, lock_file: bool) -> Iterator[Finding]:
    for flag in FLAGS:
        for match in flag.finditer(line):
            if not REFERENCE.match(match.group("value")):
                yield Finding(
                    path,
                    number,
                    "flag",
                    "mật khẩu trên dòng lệnh (-p dính giá trị, tuỳ chọn mật khẩu / token, sshpass, curl -u, "
                    "Authorization): đổi cách viết hoặc đọc từ biến môi trường",
                    masked(line, match.group("value")),
                )
    for match in URL_PASSWORD.finditer(line):
        if not REFERENCE.match(match.group("value")):
            yield Finding(path, number, "url", "địa chỉ có user:mật khẩu@", masked(line, match.group("value")))
    for name, token in TOKENS:
        for match in token.finditer(line):
            yield Finding(path, number, "token", f"giống {name}", masked(line, match.group(0)))
    if lock_file:
        return
    for match in PRIVATE_IP.finditer(line):
        yield Finding(path, number, "network", "IP nội bộ: để trong .env", masked(line, match.group(0)))
    if OPERATION_ID_FILES.search(path) and OPERATION_ID.match(line):
        return
    for match in HEX.finditer(DIGEST.sub(lambda digest: " " * len(digest.group(0)), line)):
        yield Finding(path, number, "hex", "chuỗi hex từ 32 ký tự, dạng mật khẩu của kho", masked(line, match.group(0)))


def python_strings(text: str) -> Iterator[tuple[int, str]]:
    """(line number, content) of every line of the string literals of a Python file."""
    middles = {getattr(tokenize, name) for name in ("FSTRING_MIDDLE", "TSTRING_MIDDLE") if hasattr(tokenize, name)}
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.STRING:
                body = re.sub(r"""^[rRbBuUfF]*('''|\"\"\"|'|")|('''|\"\"\"|'|")$""", "", token.string)
            elif token.type in middles:
                body = token.string
            else:
                continue
            for offset, part in enumerate(body.split("\n")):
                yield token.start[0] + offset, part
    except (tokenize.TokenError, SyntaxError):
        return  # a file Python cannot read: its lines were scanned as text anyway


def file_findings(path: str) -> Iterator[Finding]:
    parts = [plain(part).lower() for part in PurePosixPath(path).parts]
    name = parts[-1] if parts else ""
    if ENV_FILE.match(name) and name != ".env.example":
        yield Finding(path, 0, "file", "file .env chứa bí mật, không đưa vào git (đưa .env.example)")
    elif PurePosixPath(name).suffix in SECRET_SUFFIXES or any(SECRET_NAME.search(part) for part in parts):
        yield Finding(path, 0, "file", "tên file / thư mục giống nơi giữ mật khẩu hoặc khoá: không đưa vào git")


def scan_file(path: Path, name: str | None = None) -> list[Finding]:
    """What the file holds that looks like a credential. ``name`` is the path shown and checked (default: path)."""
    name = name or path.as_posix()
    found = list(file_findings(name))
    data = path.read_bytes()
    if b"\0" in data[:8192]:
        return [*found, Finding(name, 0, "file", "file nhị phân, không quét được: không đưa vào git")]
    text = data.decode("utf-8", errors="replace")
    kind = kind_of(name)
    lock_file = PurePosixPath(name).name in LOCK_FILES
    locale = bool(LOCALE.search(name))
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        if not locale:
            found += key_findings(name, number, line, kind)
        found += pattern_findings(name, number, line, lock_file)
    if kind == "python":
        for number, part in python_strings(text):
            found += key_findings(name, number, part, "text")
    unique = {(finding.line, finding.rule, finding.message): finding for finding in found}
    return sorted(unique.values(), key=lambda finding: (finding.line, finding.rule))


def tracked_files() -> list[str]:
    listed = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout.decode()
    return [path for path in listed.split("\0") if path]


def git_output(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout.decode(errors="replace")


def changed_lines(paths: Sequence[str]) -> dict[str, set[int] | None]:
    """Per path, the lines the work tree adds or changes against HEAD; None for a path HEAD does not have.

    One git call for all paths. In a commit pre-commit stashes what is not staged, so the work tree is the commit.
    """
    if not paths or subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], capture_output=True).returncode:
        return dict.fromkeys(paths)  # no commit yet: every file is new
    known = set(git_output("ls-tree", "-r", "-z", "--name-only", "HEAD", "--", *paths).split("\0"))
    changed: dict[str, set[int] | None] = {path: (set() if path in known else None) for path in paths}
    diff = git_output("diff", "--no-color", "--no-ext-diff", "--no-renames", "-U0", "HEAD", "--", *paths)
    for section in re.split(r"^diff --git ", diff, flags=re.MULTILINE)[1:]:
        target = re.search(r"^\+\+\+ b/(.+)$", section, re.MULTILINE)
        lines = changed.get(target.group(1)) if target else None
        if lines is None:
            continue  # a deleted file, or a new one scanned whole
        for hunk in HUNK.finditer(section):
            start = int(hunk.group(1))
            lines.update(range(start, start + int(hunk.group(2) or 1)))
    return changed


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    every = args == ["--all"]
    paths = tracked_files() if every else [path for path in args if Path(path).is_file()]
    files = [Path(path) for path in paths if Path(path).is_file()]
    found = [finding for file in files for finding in scan_file(file)]
    if not every:
        # a line HEAD already had is not part of this commit; findings on the whole file (line 0) always count
        changed = changed_lines(paths)
        found = [f for f in found if f.line == 0 or (lines := changed.get(f.path)) is None or f.line in lines]
    for finding in found:
        print(finding)
    if found:
        print(
            f"❌ {len(found)} chỗ giống thông tin đăng nhập trong {len({f.path for f in found})} file. Không có cách "
            "bỏ qua tại chỗ: viết lại (biến môi trường, giá trị sinh lúc chạy) hoặc sửa "
            "scripts/security/scan_secrets.py qua merge request."
        )
        return 1
    if every:
        print(f"✔ {len(files)} file, không có gì giống mật khẩu, token, khoá hay IP nội bộ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
