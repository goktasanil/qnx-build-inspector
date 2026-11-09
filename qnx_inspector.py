#!/usr/bin/env python3
"""Offline, conservative static inspection of a documented subset of QNX 8 mkifs.

No SDK imports, image building, shell execution or network access. See README.md.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import html
import json
import os
from pathlib import Path
import posixpath
import re
import sys
from typing import Any

VERSION = "0.1.0"
MKIFS = "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html"
SYNTAX = "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/buildfile_syntax.html"
SCRIPT = "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/nto_script.html"
ON = "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/o/on.html"
TARGETS = "https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.building/topic/buildfiles/nto_files_target.html"
ESC_DOLLAR = "\ue000"
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z_0-9]*)\}")
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z_0-9]*)=(.*)$", re.S)
INTERNAL = {"display_msg", "procmgr_symlink", "reopen", "waitfor"}
MODIFIERS = {"argv0", "cpu", "critical", "external", "pri", "session"}
KNOWN_ATTRS = set("autolink autoso big_pages bigendian cd chain cksum compress dperms drop dupignore filter followlink gid ifs_csa image include keeplinked keepsection linker module mount mtime optional page_align pagesizes perms phys_align physical prefix ram raw script search sha256 sha512 type uid virtual".split())


@dataclass(frozen=True)
class Position:
    file: str
    line: int
    column: int = 1


@dataclass
class Finding:
    code: str
    severity: str
    confidence: str
    message: str
    position: Position
    remedy: str
    reference: str = MKIFS
    related: list[Position] = field(default_factory=list)


@dataclass
class Entry:
    target: str | None
    source: str | None
    kind: str
    attributes: dict[str, Any]
    position: Position
    content: list[tuple[int, str]] = field(default_factory=list)
    selected: bool = True


@dataclass
class Launch:
    command: str
    position: Position
    background: bool
    identity: str
    resolution: str
    candidates: list[str]
    modifiers: dict[str, Any]


@dataclass(frozen=True)
class Token:
    value: str
    column: int
    quoted: bool = False


class SyntaxIssue(ValueError):
    def __init__(self, message: str, column: int = 1):
        super().__init__(message)
        self.column = column


def tokenize(text: str, *, equals: bool = False, comments: bool = True) -> list[Token]:
    """Double-quoted fields, documented escapes, optional unquoted '=' separator.

    Deliberately not shlex: a QNX buildfile isn't a POSIX shell program.
    Escaped dollars remain marked until after explicit variable expansion.
    """
    result: list[Token] = []
    buf: list[str] = []
    start = 0
    active = False
    quoted = False
    had_quote = False
    i = 0
    while i < len(text):
        c = text[i]
        if not quoted and comments and c == "#" and (i == 0 or text[i - 1].isspace()):
            break
        if c == '"':
            if not active:
                start, active = i, True
            quoted = not quoted
            had_quote = True
            i += 1
            continue
        if c == "\\" and i + 1 < len(text) and text[i + 1] in '\\"$]':
            if not active:
                start, active = i, True
            nxt = text[i + 1]
            buf.append(ESC_DOLLAR if nxt == "$" else nxt)
            i += 2
            continue
        if not quoted and (c.isspace() or (equals and c == "=")):
            if active:
                result.append(Token("".join(buf), start + 1, had_quote))
                buf, active, had_quote = [], False, False
            if c == "=":
                result.append(Token("=", i + 1))
            i += 1
            continue
        if not active:
            start, active = i, True
        buf.append(c)
        i += 1
    if quoted:
        raise SyntaxIssue("Unclosed double-quoted field.", start + 1)
    if active:
        result.append(Token("".join(buf), start + 1, had_quote))
    return result


def leading_attributes(text: str) -> tuple[str | None, str, int]:
    offset = len(text) - len(text.lstrip())
    if not text.lstrip().startswith("["):
        return None, text, 0
    quoted = False
    escaped = False
    for i in range(offset + 1, len(text)):
        c = text[i]
        if escaped:
            escaped = False
        elif c == "\\":
            escaped = True
        elif c == '"':
            quoted = not quoted
        elif c == "]" and not quoted:
            return text[offset + 1:i], text[i + 1:], i + 1
    raise SyntaxIssue("Unclosed attribute/modifier group.", offset + 1)


def normalize_target(path: str) -> str:
    return posixpath.normpath("/" + path.lstrip("/"))


def public_value(value: Any) -> Any:
    """Remove internal escaped-dollar markers from serialized evidence."""
    if isinstance(value, str):
        return value.replace(ESC_DOLLAR, "$")
    if isinstance(value, dict):
        return {key: public_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [public_value(item) for item in value]
    return value


class Inspector:
    def __init__(self, *, cwd: Path, project_root: Path, variables: dict[str, str] | None = None,
                 check_host_files: bool = False, include_dirs: list[Path] | None = None):
        self.cwd = cwd.resolve()
        self.project_root = project_root.resolve()
        self.variables = dict(variables or {})
        self.variables.setdefault("PFS", os.pathsep)
        self.check_host_files = check_host_files
        self.include_dirs = [p.resolve() for p in include_dirs or []]
        self.findings: list[Finding] = []
        self.entries: list[Entry] = []
        self.launches: list[Launch] = []
        self.sources: dict[str, list[str]] = {}
        self.source_hashes: dict[str, str] = {}
        self.dependencies: list[dict[str, Any]] = []
        self.global_attrs: dict[str, Any] = {}
        self.visited: set[Path] = set()
        self.active: list[Path] = []
        self.bootable = False
        self.runtime_env: dict[str, str] = {}
        self.partial_reasons: set[str] = set()
        self.total_bytes = 0

    def label(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.project_root).as_posix()
        except ValueError:
            return path.name

    def issue(self, code: str, severity: str, confidence: str, message: str, pos: Position,
              remedy: str, reference: str = MKIFS, related: list[Position] | None = None) -> None:
        self.findings.append(Finding(code, severity, confidence, message, pos, remedy,
                                     reference, related or []))
        if code.startswith("C") or code.startswith("P"):
            self.partial_reasons.add(code)

    def expand(self, value: str) -> tuple[str, bool]:
        unresolved = False
        def replace(match: re.Match[str]) -> str:
            nonlocal unresolved
            name = match.group(1)
            if name not in self.variables:
                unresolved = True
                return match.group(0)
            return self.variables[name]
        # One pass only: recursive/default/command expansions are not interpreted.
        expanded = VAR.sub(replace, value)
        if VAR.search(expanded):
            unresolved = True
        return expanded.replace(ESC_DOLLAR, "$"), unresolved

    def attributes(self, group: str | None, base: dict[str, Any], pos: Position,
                   *, script: bool = False) -> dict[str, Any]:
        attrs = dict(base)
        if group is None:
            return attrs
        allowed = MODIFIERS if script else KNOWN_ATTRS
        for token in tokenize(group, comments=False):
            raw = token.value
            conditional = raw.startswith("?")
            raw = raw[1:] if conditional else raw
            if raw.startswith(("+", "-")):
                key, value = raw[1:], raw[0] == "+"
            elif "=" in raw:
                key, value = raw.split("=", 1)
            else:
                self.issue("P104", "warning", "high", f"Attribute token {raw!r} is outside the supported grammar.", pos,
                           "Use a documented boolean or name=value attribute; validate advanced syntax with mkifs.")
                continue
            if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key):
                self.issue("P104", "warning", "high", f"Cannot interpret attribute {raw!r}.", pos,
                           "Check attribute spelling and omit spaces around '='.")
                continue
            if key not in allowed:
                code = "S301" if script else "C104"
                self.issue(code, "error" if script else "info", "high",
                           f"{key}= is not a documented mkifs script modifier." if script else f"Unrecognized attribute {key!r}; semantics are not modeled.",
                           pos, "File uid= sets ownership, not process credentials. Review the on -u utility for process identity." if script and key == "uid" else "Check the QNX 8 reference and validate with mkifs.",
                           SCRIPT if script else MKIFS)
            if script and key in allowed:
                boolean = key in {"critical", "external", "session"}
                if (boolean and not isinstance(value, bool)) or (not boolean and (isinstance(value, bool) or not value)):
                    self.issue("S305", "error", "high", f"Invalid value/boolean form for script modifier {key!r}.", pos,
                               "Use +/- for critical, external and session; use name=value for argv0, cpu and pri.", SCRIPT)
            if not conditional or key not in attrs:
                attrs[key] = value
        return attrs

    def resolve_host(self, source: str, attrs: dict[str, Any], *, include: bool = False) -> tuple[Path | None, bool]:
        expanded, unknown = self.expand(source)
        search, search_unknown = self.expand(str(attrs.get("search", self.variables.get("MKIFS_PATH", ""))))
        candidates: list[Path] = []
        if Path(expanded).is_absolute():
            candidates.append(Path(expanded))
        elif re.match(r"^[A-Za-z]:[\\/]", expanded) and os.name != "nt":
            return None, True
        else:
            # Includes always try CWD. Ordinary basename-only sources go directly
            # to search; mkifs tries CWD first only for relative paths with '/'.
            if include or "/" in expanded or "\\" in expanded:
                candidates.append(self.cwd / expanded)
            for directory in search.split(self.variables["PFS"]):
                if directory:
                    p = Path(directory)
                    candidates.append((p if p.is_absolute() else self.cwd / p) / expanded)
            if include:
                candidates.extend(directory / expanded for directory in self.include_dirs)
        if unknown:
            return None, True
        for candidate in candidates:
            if candidate.exists():
                return candidate.resolve(), False
        return None, search_unknown

    def read(self, path: Path, origin: Position | None = None) -> None:
        path = path.resolve()
        pos = origin or Position(self.label(path), 1)
        if path in self.active:
            self.issue("I201", "error", "high", "Circular buildfile inclusion detected.", pos,
                       "Break the include cycle: " + " -> ".join(self.label(p) for p in self.active + [path]))
            return
        if path in self.visited:
            self.issue("I202", "info", "high", "Repeated buildfile inclusion is ignored, matching mkifs.", pos,
                       "Remove the redundant inclusion if it obscures the buildfile stream.")
            return
        if len(self.active) >= 32 or len(self.visited) >= 128:
            self.issue("C201", "error", "high", "Analysis include depth/file limit reached.", pos,
                       "Analyze a smaller, explicitly scoped buildfile tree.")
            return
        try:
            if path.stat().st_size + self.total_bytes > 4 * 1024 * 1024:
                raise ValueError("The combined input limit is 4 MiB.")
            data = path.read_bytes()
            self.total_bytes += len(data)
            if self.total_bytes > 4 * 1024 * 1024:
                raise ValueError("The combined input limit is 4 MiB.")
            text = data.decode("utf-8-sig")
        except (OSError, UnicodeError, ValueError) as exc:
            self.issue("P101", "error", "high", f"Cannot read UTF-8 buildfile: {exc}", pos,
                       "Check the path, encoding and 4 MiB input limit.")
            return
        self.visited.add(path)
        self.active.append(path)
        label = self.label(path)
        lines = text.splitlines()
        self.sources[label] = lines
        self.source_hashes[label] = hashlib.sha256(data).hexdigest()
        index = 0
        while index < len(lines):
            line_number = index + 1
            line = lines[index]
            index += 1
            # Continuations are recognized outside inline bodies only.
            while len(line) - len(line.rstrip("\\")) & 1:
                if index == len(lines):
                    self.issue("P102", "error", "high", "Dangling line continuation.", Position(label, line_number),
                               "Finish the continued buildfile line.")
                    break
                line = line[:-1] + lines[index]
                index += 1
            pos = Position(label, line_number, len(line) - len(line.lstrip()) + 1)
            try:
                group, rest, offset = leading_attributes(line)
                tokens = tokenize(rest, equals=True)
                if tokens and tokens[0].value.startswith("["):
                    raise SyntaxIssue("Combine attributes in one bracket group per buildfile line.", offset + tokens[0].column)
                attrs = self.attributes(group, self.global_attrs, pos)
                if not tokens:
                    self.global_attrs = attrs
                    continue
                if len(tokens) == 1:
                    target_spec, source, inline = tokens[0].value, tokens[0].value, False
                    alias = False
                elif len(tokens) == 3 and tokens[1].value == "=":
                    target_spec, source = tokens[0].value, tokens[2].value
                    inline, alias = source == "{", True
                else:
                    raise SyntaxIssue("Expected one path, target=host, or target={ on its own line.", offset + tokens[0].column)
                content: list[tuple[int, str]] = []
                if inline:
                    closed = False
                    while index < len(lines):
                        body = lines[index]
                        body_line = index + 1
                        index += 1
                        # Find the first unescaped '}', independent of comments or quotes.
                        decoded: list[str] = []
                        j = 0
                        while j < len(body):
                            if body[j] == "\\" and j + 1 < len(body):
                                decoded.append(body[j + 1])
                                j += 2
                            elif body[j] == "\\":
                                # In an inline file the escaped newline is copied,
                                # retaining the line break rather than joining lines.
                                j += 1
                            elif body[j] == "}":
                                closed = True
                                if "".join(decoded).strip() or body[j + 1:].strip():
                                    self.issue("P105", "error", "high", "Inline closing brace must be on its own line.", Position(label, body_line, j + 1),
                                               "Escape literal braces in inline contents; put the closing brace on a separate line.", SYNTAX)
                                break
                            else:
                                decoded.append(body[j])
                                j += 1
                        if closed:
                            break
                        content.append((body_line, "".join(decoded)))
                    if not closed:
                        self.issue("P106", "error", "high", "Unclosed inline file; remaining lines are treated as its contents.", pos,
                                   "Add a separate closing-brace line; escape literal braces.", SYNTAX)
                if attrs.get("include"):
                    if inline or alias:
                        self.issue("I203", "error", "high", "Buildfile inclusion cannot use target=host or inline notation.", pos,
                                   "Use [+include] path_to_buildfile.")
                        continue
                    included, uncertain = self.resolve_host(source, attrs, include=True)
                    dep = {"kind": "include", "source": source, "from": asdict(pos), "resolved": self.label(included) if included else None}
                    self.dependencies.append(dep)
                    if included is None:
                        self.issue("C202" if uncertain else "I204", "warning" if uncertain or attrs.get("optional") else "error", "limited" if uncertain else "high",
                                   f"Include {source!r} is unresolved." if uncertain else f"Include {source!r} was not found in the configured lookup paths.", pos,
                                   "Pass explicit --define variables/search paths; use --include-dir for SDK/root boot/build directories. Optional includes may intentionally be absent.")
                    elif not included.is_relative_to(self.project_root):
                        self.issue("C203", "warning", "high", "Include resolves outside --project-root and was not read.", pos,
                                   "Set --project-root to a trusted common ancestor if this include should be analyzed.")
                    else:
                        self.read(included, pos)
                    continue
                if "virtual" in attrs or "physical" in attrs:
                    self.bootable = True
                    if self.entries:
                        self.issue("B201", "error", "high", "Bootstrap file is not the first file specification.", pos,
                                   "Move the bootfile before image file entries.")
                target_text, unknown = self.expand(target_spec)
                mount, mount_unknown = self.expand(str(attrs.get("mount", "/")))
                prefix, prefix_unknown = self.expand(str(attrs.get("prefix", "proc/boot" if self.bootable else "")))
                target: str | None = None
                if unknown or mount_unknown or prefix_unknown or mount != "/":
                    self.issue("C204", "info", "limited", "Target path cannot be mapped confidently (variable or non-default mount).", pos,
                               "Use explicit --define values. Non-default mounts require mkifs/dumpifs verification; path-dependent checks are skipped for this entry.")
                else:
                    name = target_text if alias else target_text.replace("\\", "/").rsplit("/", 1)[-1]
                    target = normalize_target(name if name.startswith("/") else prefix + "/" + name)
                kind = "bootstrap" if "virtual" in attrs or "physical" in attrs else "script" if attrs.get("script") else str(attrs.get("type", "file"))
                if inline and kind not in {"file", "script", "bootstrap"}:
                    self.issue("C205", "warning", "limited", f"Inline content with type={kind} is outside this analyzer's model.", pos,
                               "Validate this combination with mkifs.")
                entry = Entry(target, None if inline else source, kind, attrs, pos, content)
                self.entries.append(entry)
                for owner_attr in ("uid", "gid"):
                    if owner_attr in attrs:
                        owner, uncertain = self.expand(str(attrs[owner_attr]))
                        if not uncertain and owner != "*" and not re.fullmatch(r"[0-9]+", owner):
                            self.issue("F202", "error", "high", f"File {owner_attr}={owner!r} must be numeric or '*'.", pos,
                                       "Use a numeric file owner/group ID, or '*' to inherit host ownership.")
                if "cd" in attrs or "drop" in attrs:
                    self.issue("C206", "warning", "limited", "cd/drop attributes affect file selection and are not modeled.", pos,
                               "Use explicit file entries for precise inventory checks; verify the resulting image with dumpifs.")
                if entry.source and kind not in {"link", "dir", "fifo"} and self.check_host_files and not attrs.get("cd"):
                    resolved, uncertain = self.resolve_host(entry.source, attrs)
                    self.dependencies.append({"kind": "host-file", "source": entry.source, "from": asdict(pos), "resolved": self.label(resolved) if resolved else None})
                    if resolved is None:
                        self.issue("C207" if uncertain else "H201", "info" if uncertain else "warning" if attrs.get("optional") else "error", "limited" if uncertain else "high",
                                   f"Host source {entry.source!r} is unresolved." if uncertain else f"Host source {entry.source!r} was not found in configured lookup paths.", pos,
                                   "Supply the build's actual CWD, search variables and files; no SDK paths are guessed.")
                        if attrs.get("optional") and not uncertain:
                            entry.selected = False
                    elif resolved.is_dir():
                        self.issue("C208", "info", "high", "Directory import is not expanded; inventory is incomplete.", pos,
                                   "Use explicit file entries or inspect the built image with dumpifs.")
                if entry.source and kind in {"script", "bootstrap"}:
                    self.issue("C209", "warning", "high", f"External {kind} content is not read by this version.", pos,
                               "Use an inline script/bootstrap for analysis, or review its content separately.")
            except SyntaxIssue as exc:
                self.issue("P103", "error", "high", str(exc), Position(label, line_number, exc.column),
                           "Correct the reported line; this is a supported-subset parse error, not mkifs validation.", SYNTAX)
        self.active.pop()

    def inventory(self) -> dict[str, Entry]:
        table: dict[str, Entry] = {}
        for entry in self.entries:
            if entry.target is None or not entry.selected:
                continue
            if entry.target in table:
                previous = table[entry.target]
                old_ignore = bool(previous.attributes.get("dupignore"))
                new_ignore = bool(entry.attributes.get("dupignore"))
                if old_ignore or new_ignore:
                    if old_ignore and not new_ignore:
                        previous.selected = False
                        table[entry.target] = entry
                    else:
                        entry.selected = False
                    self.issue("D202", "info", "high", f"Duplicate target {entry.target}; +dupignore selects one entry.", entry.position,
                               "Confirm that the selected inventory source is intentional.", related=[previous.position])
                else:
                    self.issue("D201", "error", "high", f"Duplicate image target {entry.target}.", entry.position,
                               "Remove the duplicate or intentionally configure +dupignore; mkifs rejects two non-ignored entries.", related=[previous.position])
            else:
                table[entry.target] = entry
        for target, entry in table.items():
            parent = posixpath.dirname(target)
            while parent != "/":
                ancestor = table.get(parent)
                if ancestor and ancestor.kind not in {"dir"}:
                    self.issue("D203", "error", "high", f"Target {target} is below a declared {ancestor.kind} at {parent}.", entry.position,
                               "Use a real directory. mkifs does not resolve IFS symlinks in other entry pathnames.", related=[ancestor.position])
                    break
                parent = posixpath.dirname(parent)
            mode = str(entry.attributes.get("perms", "*"))
            if re.fullmatch(r"0?[0-7]{3,4}", mode):
                bits = int(mode, 8)
                if bits & 0o002 and bits & 0o6000:
                    self.issue("F201", "warning", "high", f"Explicit mode {mode} combines world write with set-ID bits on {target}.", entry.position,
                               "Review the explicit permissions and ownership; this is a policy review, not proof of exploitability.")
        for target, entry in table.items():
            if entry.kind == "link":
                _, status = self.follow_link(target, table, {})
                if status == "cycle":
                    self.issue("D204", "error", "high", f"Symbolic-link cycle starts at {target}.", entry.position,
                               "Point at a concrete target or break the cycle.")
        return table

    def follow_link(self, path: str, table: dict[str, Entry], runtime_links: dict[str, str]) -> tuple[str, str]:
        seen: set[str] = set()
        while True:
            if path in seen:
                return path, "cycle"
            seen.add(path)
            entry = table.get(path)
            destination = runtime_links.get(path)
            if destination is None and entry and entry.kind == "link":
                destination = entry.source
            if destination is None:
                return path, "listed" if entry and entry.kind not in {"dir", "fifo", "script", "bootstrap"} else "not-listed"
            destination, unknown = self.expand(destination)
            if unknown:
                return path, "unresolved"
            path = normalize_target(destination if destination.startswith("/") else posixpath.dirname(path) + "/" + destination)

    def script_lines(self, entry: Entry) -> list[tuple[int, str]]:
        return entry.content

    def inspect_scripts(self, table: dict[str, Entry]) -> None:
        # Bootstrap assignments seed subsequent scripts. Bootstrap executables are
        # not ordinary image dependencies and aren't linted as user-process launches.
        for entry in self.entries:
            if entry.kind == "bootstrap":
                for _, text in entry.content:
                    try:
                        tokens = tokenize(text)
                    except SyntaxIssue:
                        continue
                    if len(tokens) == 1 and (match := ASSIGN.match(tokens[0].value)):
                        self.runtime_env[match.group(1)] = self.expand(match.group(2))[0]
        modifiers: dict[str, Any] = {}
        runtime_links: dict[str, str] = {}
        pending_foreground: tuple[str, Position] | None = None
        for entry in self.entries:
            if entry.kind != "script" or not entry.selected:
                continue
            for number, text in self.script_lines(entry):
                pos = Position(entry.position.file, number, len(text) - len(text.lstrip()) + 1)
                try:
                    group, rest, _ = leading_attributes(text)
                    attrs = self.attributes(group, modifiers, pos, script=True)
                    tokens = tokenize(rest)
                    if not tokens:
                        modifiers = attrs
                        continue
                    env = dict(self.runtime_env)
                    while tokens and (match := ASSIGN.match(tokens[0].value)):
                        env[match.group(1)] = self.expand(match.group(2))[0]
                        tokens.pop(0)
                    if not tokens:
                        self.runtime_env = env
                        continue
                    if pending_foreground:
                        command, previous_pos = pending_foreground
                        self.issue("S304", "info", "heuristic", f"Foreground launch {command!r} precedes another command.", previous_pos,
                                   "Confirm that it exits; a process that remains in the foreground prevents later startup commands.", SCRIPT)
                        pending_foreground = None
                    # Operators are only rejected when they are standalone tokens;
                    # no claims are made about a shell interpreter's quoted arguments.
                    if any(not t.quoted and t.value in {"|", ">", ">>", "<", "&&", "||", ";"} for t in tokens):
                        self.issue("S302", "error", "high", "Shell operators are not supported by mkifs startup scripts.", pos,
                                   "Use separate startup commands or invoke an included shell explicitly for shell syntax.", SCRIPT)
                        continue
                    background = tokens[-1].value == "&" and not tokens[-1].quoted
                    if background:
                        tokens.pop()
                    if not tokens:
                        raise SyntaxIssue("Missing command before '&'.")
                    command, unresolved = self.expand(tokens[0].value)
                    args = [self.expand(t.value)[0] for t in tokens[1:]]
                    if command in INTERNAL and not attrs.get("external"):
                        if command == "procmgr_symlink" and len(args) == 2 and args[1].startswith("/"):
                            runtime_links[normalize_target(args[1])] = args[0]
                        continue
                    if command in {"if", "for", "while", "case", "then", "fi", "done"}:
                        self.issue("S303", "error", "high", "Shell control flow is not supported by mkifs startup scripts.", pos,
                                   "Move control flow into an included shell script and launch the shell explicitly.", SCRIPT)
                        continue
                    self.add_launch(command, pos, background, "inherited/unknown", attrs, env, table, runtime_links, unresolved)
                    if posixpath.basename(command) == "on":
                        nested, identity, detached = self.on_command(args, pos)
                        background = background or detached
                        if nested:
                            self.add_launch(nested, pos, background, identity, attrs, env, table, runtime_links, "${" in nested)
                    if not background:
                        pending_foreground = command, pos
                except SyntaxIssue as exc:
                    self.issue("P301", "error", "high", str(exc), Position(pos.file, pos.line, exc.column),
                               "Check startup-script quoting/modifier syntax; mkifs remains authoritative.", SCRIPT)

    def on_command(self, args: list[str], pos: Position) -> tuple[str | None, str, bool]:
        identity = "inherited/unknown"
        detached = False
        i = 0
        value_options = {"-A", "-C", "-c", "-e", "-L", "-p", "-R", "-S", "-T", "-t", "-u", "-W", "-w", "-X"}
        flag_options = {"-ad", "-ae", "-d", "-E", "-h", "-s", "--critical"}
        while i < len(args):
            arg = args[i]
            if arg == "--":
                i += 1
                break
            if not arg.startswith("-"):
                break
            option = arg[:2] if arg[:2] in value_options else arg
            if option in value_options:
                value = arg[2:]
                if not value:
                    i += 1
                    if i >= len(args):
                        self.issue("S401", "error", "high", f"on {option} is missing its value.", pos,
                                   "Provide the documented option argument.", ON)
                        return None, identity, detached
                    value = args[i]
                if option == "-u":
                    identity = "requested:" + value
                    uid = value.split(":", 1)[0]
                    if uid in {"0", "root"}:
                        self.issue("S402", "warning", "high", "The on wrapper explicitly requests the root identity.", pos,
                                   "Document why this process needs root; consider a dedicated UID and required abilities after target validation.", ON)
                if option == "-t":
                    detached = True
                if option == "-e":
                    self.issue("C402", "info", "limited", "on -e changes the wrapped process environment; nested launch is not inferred.", pos,
                               "Review the wrapped command's PATH/environment on the target.", ON)
                    return None, identity, detached
            elif arg in flag_options:
                detached = detached or arg == "-d"
                if arg == "-E":
                    self.issue("C402", "info", "limited", "on -E changes environment handling; nested launch is not inferred.", pos,
                               "Review the wrapped command's environment on the target.", ON)
                    return None, identity, detached
            else:
                self.issue("C401", "info", "limited", f"Unmodeled on option {arg!r}; nested launch not inferred.", pos,
                           "Use documented options or review the wrapped command manually.", ON)
                return None, identity, detached
            i += 1
        return (args[i] if i < len(args) else None), identity, detached

    def add_launch(self, command: str, pos: Position, background: bool, identity: str,
                   attrs: dict[str, Any], env: dict[str, str], table: dict[str, Entry],
                   runtime_links: dict[str, str], unresolved: bool) -> None:
        candidates: list[str] = []
        if command.startswith("/") and not unresolved:
            candidates = [normalize_target(command)]
        elif "/" not in command and "PATH" in env and not unresolved and "${" not in env["PATH"]:
            parts = env["PATH"].split(":")
            candidates = [normalize_target(p + "/" + command) for p in parts if p.startswith("/")]
            if any(not p.startswith("/") for p in parts):
                unresolved = True
        else:
            unresolved = True
        statuses = [self.follow_link(p, table, runtime_links)[1] for p in candidates]
        resolution = "listed" if "listed" in statuses else "unresolved" if unresolved or "unresolved" in statuses else "not-listed"
        self.launches.append(Launch(command, pos, background, identity, resolution, candidates, dict(attrs)))
        if resolution == "not-listed":
            self.issue("L201", "warning", "heuristic", f"Launch {command!r} is not listed at its candidate image paths.", pos,
                       "Add the executable/alias or document the filesystem that makes it available before this launch. This is not proof it is absent at runtime.", SCRIPT)
        elif resolution == "unresolved":
            self.issue("C301", "info", "limited", f"Launch {command!r} has an unresolved path or environment.", pos,
                       "Provide a literal absolute command or an explicit absolute PATH; review external filesystems separately.", SCRIPT)

    def run(self, path: Path) -> dict[str, Any]:
        self.read(path)
        table = self.inventory()
        self.inspect_scripts(table)
        self.findings.sort(key=lambda f: (f.position.file, f.position.line, f.position.column, f.code))
        return public_value({
            "tool": "QNX Build Inspector", "version": VERSION, "schema_version": 1,
            "analysis": "partial-static-analysis", "target": "QNX OS 8.0 mkifs buildfiles",
            "input": self.label(path), "compiler_or_runtime_validation": False,
            "host_file_checks": self.check_host_files,
            "summary": {"files": len(self.sources), "entries": len(self.entries), "launches": len(self.launches),
                        **{severity: sum(f.severity == severity for f in self.findings) for severity in ("error", "warning", "info")}},
            "coverage_limits": sorted(self.partial_reasons),
            "findings": [asdict(f) for f in self.findings],
            "entries": [public_value(asdict(e)) for e in self.entries],
            "launches": [asdict(launch) for launch in self.launches],
            "dependencies": self.dependencies,
            "sources": self.sources,
            "source_sha256": self.source_hashes,
        })


def human_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [f"QNX Build Inspector {VERSION} | {report['input']}",
             f"{summary['files']} files, {summary['entries']} entries, {summary['launches']} launches | "
             f"{summary['error']} errors, {summary['warning']} warnings, {summary['info']} notes",
             "Partial static analysis; no compilation, SDK or QNX runtime validation."]
    for finding in report["findings"]:
        p = finding["position"]
        lines.extend([f"{p['file']}:{p['line']}:{p['column']} {finding['severity'].upper()} {finding['code']} [{finding['confidence']}] {finding['message']}",
                      f"  Action: {finding['remedy']}"])
    return "\n".join(lines) + "\n"


def html_report(report: dict[str, Any]) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    file_ids = {name: f"source-{i}" for i, name in enumerate(report["sources"])}
    def location(p: dict[str, Any]) -> str:
        anchor = file_ids.get(p["file"], "") + f"-L{p['line']}"
        return f'<a href="#{anchor}">{esc(p["file"])}:{p["line"]}:{p["column"]}</a>'
    cards = []
    for finding in report["findings"]:
        related = "".join(f"<span>Related: {location(p)}</span>" for p in finding["related"])
        cards.append(f'<article class="finding {esc(finding["severity"])}" data-severity="{esc(finding["severity"])}"><div class="meta"><b>{esc(finding["code"])}</b><span>{esc(finding["severity"])}</span><span>{esc(finding["confidence"])} confidence</span>{location(finding["position"])}</div><h3>{esc(finding["message"])}</h3><p>{esc(finding["remedy"])}</p><footer>{related}<a href="{esc(finding["reference"])}" rel="noreferrer">QNX 8 documentation ↗</a></footer></article>')
    inventory_rows = "".join(f'<tr><td><code>{esc(e["target"] or "unresolved")}</code></td><td>{esc(e["kind"])}</td><td><code>{esc(e["source"] or "inline")}</code></td><td>{"selected" if e["selected"] else "ignored"}</td><td>{location(e["position"])}</td></tr>' for e in report["entries"])
    launches = "".join(f'<tr><td><code>{esc(launch["command"])}</code></td><td>{esc(launch["resolution"])}</td><td>{esc(launch["identity"])}</td><td>{"background" if launch["background"] else "foreground"}</td><td>{location(launch["position"])}</td></tr>' for launch in report["launches"])
    sources = []
    for name, lines in report["sources"].items():
        source_lines = "".join(f'<div id="{file_ids[name]}-L{i}" class="source-line"><a href="#{file_ids[name]}-L{i}">{i}</a><code>{esc(line)}</code></div>' for i, line in enumerate(lines, 1))
        sources.append(f'<details open><summary>{esc(name)}</summary><div class="source">{source_lines}</div></details>')
    summary = report["summary"]
    metrics = "".join(f'<div><strong>{summary[key]}</strong><span>{label}</span></div>' for key, label in (("error", "Errors"), ("warning", "Warnings"), ("info", "Review notes"), ("entries", "Image entries")))
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'"><title>QNX Build Inspector · {esc(report['input'])}</title>
<style>
:root{{color-scheme:dark;--bg:#0a1220;--panel:#111e32;--text:#e5edf8;--muted:#9eafc6;--line:#273a53;--cyan:#5be0d1}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}}a{{color:#83caff}}main{{max-width:1150px;margin:auto;padding:40px 24px 70px}}.eyebrow{{letter-spacing:.14em;text-transform:uppercase;font-size:12px;color:var(--cyan);font-weight:700}}h1{{font-size:42px;line-height:1.15;margin:12px 0}}h2{{font-size:25px;margin:38px 0 14px}}h3{{font-size:17px;line-height:1.5;margin:14px 0 8px}}p{{margin:8px 0}}.muted{{color:var(--muted)}}.banner{{border:1px solid var(--line);background:#112437;border-radius:12px;padding:17px 20px;margin:24px 0}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:24px 0}}.metrics>div{{background:var(--panel);border:1px solid var(--line);padding:16px 20px;border-radius:12px}}.metrics strong{{font-size:31px;display:block;line-height:1.3}}.metrics span{{color:var(--muted)}}nav{{display:flex;gap:12px;flex-wrap:wrap}}nav a,.filters button{{border:1px solid var(--line);border-radius:8px;padding:8px 13px;text-decoration:none;background:var(--panel);color:var(--text);font:inherit;cursor:pointer}}.filters{{display:flex;gap:9px;align-items:center;flex-wrap:wrap}}.filters button[aria-pressed=true]{{border-color:var(--cyan);color:var(--cyan)}}.finding{{border:1px solid var(--line);border-left:4px solid #6aa6ee;border-radius:10px;background:var(--panel);padding:18px 20px;margin:14px 0}}.finding.error{{border-left-color:#ff808b}}.finding.warning{{border-left-color:#ffcb7a}}.finding[hidden]{{display:none}}.meta,footer{{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--muted)}}.meta b{{color:var(--text)}}footer{{margin-top:12px;justify-content:space-between}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{padding:11px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted)}}.table-wrap{{overflow:auto;background:var(--panel);border-radius:10px;border:1px solid var(--line)}}code{{font-family:ui-monospace,Consolas,monospace;word-break:break-word}}details{{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:14px 0;overflow:hidden}}summary{{padding:13px 17px;cursor:pointer;color:var(--cyan)}}.source{{overflow:auto;padding-bottom:12px}}.source-line{{display:flex;min-width:max-content;padding-right:18px;line-height:1.8;font-size:12px}}.source-line a{{width:48px;flex:none;text-align:right;padding-right:14px;color:#7d91ad;text-decoration:none;user-select:none}}.source-line code{{white-space:pre}}.source-line:target{{background:#354535}}.endnote{{font-size:12px;color:var(--muted);margin-top:36px}}@media(max-width:640px){{h1{{font-size:32px}}main{{padding:24px 15px}}.metrics{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body><main><div class="eyebrow">Offline developer tooling · QNX OS 8.0</div><h1>Inspect before you build.</h1><p class="muted">{esc(report['input'])} · QNX Build Inspector {VERSION}</p><div class="banner"><b>Partial static analysis</b><p>No QNX SDK, compiler, image or target was run. “Listed” means represented in the modeled image inventory, not executable, secure or bootable. Missing launch references may be supplied by external filesystems.</p></div><div class="metrics">{metrics}</div><nav><a href="#findings">Findings</a><a href="#inventory">Image inventory</a><a href="#launches">Launch map</a><a href="#sources">Source evidence</a></nav><section id="findings"><h2>Actionable findings</h2><div class="filters" role="group" aria-label="Filter findings"><button data-filter="all" aria-pressed="true">All</button><button data-filter="error" aria-pressed="false">Errors</button><button data-filter="warning" aria-pressed="false">Warnings</button><button data-filter="info" aria-pressed="false">Review notes</button><span class="muted" id="visible-count" aria-live="polite"></span></div>{''.join(cards) or '<p>No findings in the supported model. This is not a build validation.</p>'}</section><section id="inventory"><h2>Image inventory</h2><div class="table-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Host source</th><th>Selection</th><th>Evidence</th></tr></thead><tbody>{inventory_rows}</tbody></table></div></section><section id="launches"><h2>Launch map</h2><p class="muted">Identity is inferred only for an explicit on -u request. File uid= is not a process identity setting.</p><div class="table-wrap"><table><thead><tr><th>Command</th><th>Inventory match</th><th>Identity evidence</th><th>Mode</th><th>Source</th></tr></thead><tbody>{launches}</tbody></table></div></section><section id="sources"><h2>Source evidence</h2>{''.join(sources)}</section><p class="endnote">Independent tool by Anıl Göktaş. Not QNX certified or endorsed. This report contains the analyzed source text. Findings use the documented subset described in the project README. Coverage markers: {esc(', '.join(report['coverage_limits']) or 'none encountered')}.</p></main><script>
const buttons=document.querySelectorAll('[data-filter]'),cards=document.querySelectorAll('.finding');for(const button of buttons){{button.addEventListener('click',()=>{{let count=0;for(const card of cards){{card.hidden=button.dataset.filter!=='all'&&card.dataset.severity!==button.dataset.filter;if(!card.hidden)count++;}}for(const peer of buttons)peer.setAttribute('aria-pressed',String(peer===button));document.getElementById('visible-count').textContent=count+' shown';}});}}
</script></body></html>'''


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("buildfile", type=Path)
    parser.add_argument("--cwd", type=Path, default=Path.cwd(), help="Actual mkifs CWD for resolving host paths (default: current directory).")
    parser.add_argument("--project-root", type=Path, help="Trust boundary for includes (default: top buildfile's directory).")
    parser.add_argument("--define", action="append", default=[], metavar="NAME=VALUE", help="Explicit host variable, repeatable; ambient environment is not imported.")
    parser.add_argument("--include-dir", type=Path, action="append", default=[], help="Additional include lookup directory; no SDK paths are guessed.")
    parser.add_argument("--check-host-files", action="store_true", help="Check source existence using the configured CWD/search values; does not inspect binaries.")
    parser.add_argument("--json", type=Path, dest="json_output", help="Write machine-readable report including source text.")
    parser.add_argument("--html", type=Path, dest="html_output", help="Write a self-contained offline HTML report.")
    parser.add_argument("--fail-on", choices=("error", "warning", "never"), default="error", help="Exit 1 when selected severity is present (default: error).")
    args = parser.parse_args(argv)
    variables = {}
    for definition in args.define:
        match = ASSIGN.match(definition)
        if not match:
            parser.error("--define must be NAME=VALUE")
        variables[match.group(1)] = match.group(2)
    inspector = Inspector(cwd=args.cwd, project_root=args.project_root or args.buildfile.resolve().parent,
                          variables=variables, check_host_files=args.check_host_files, include_dirs=args.include_dir)
    report = inspector.run(args.buildfile)
    print(human_report(report), end="")
    try:
        if args.json_output:
            args.json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if args.html_output:
            args.html_output.write_text(html_report(report), encoding="utf-8")
    except OSError as exc:
        print(f"Cannot write report: {exc}", file=sys.stderr)
        return 2
    return int(args.fail_on != "never" and (report["summary"]["error"] > 0 or (args.fail_on == "warning" and report["summary"]["warning"] > 0)))


if __name__ == "__main__":
    raise SystemExit(main())
