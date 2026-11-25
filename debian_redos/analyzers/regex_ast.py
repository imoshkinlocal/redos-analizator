"""Regular-expression parser and static metrics.

This module is deliberately independent from any particular implementation of
the analyser: it turns a pattern string for a known dialect into a normalised
AST with character-set semantics, so that the NFA builder, the heuristics and
the attack generator all speak the same language.

Supported syntax covers the constructs that occur in real Debian sources:
groups (capturing/non-capturing/atomic/named), alternation, quantifiers
(greedy/lazy/possessive), character classes with POSIX shorthands, anchors,
lookarounds, backreferences and inline flags.  Constructs that cannot be
modelled soundly (recursion, conditionals, callouts, absent operator) are kept
as ``Unsupported`` nodes so the analysis can be marked partial instead of
silently wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

MAX_CP = 0x10FFFF
DIGITS = "0123456789"
WORD = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
SPACE = " \t\n\r\f\v"
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_ESCAPE_CHARS = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v",
                 "a": "\a", "e": "\x1b", "0": "\0"}
_POSIX = {
    "alpha": LETTERS,
    "digit": DIGITS,
    "alnum": LETTERS + DIGITS,
    "space": SPACE,
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "xdigit": "0123456789ABCDEFabcdef",
    "word": WORD,
    "punct": "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "cntrl": "".join(chr(i) for i in range(0x20)) + "\x7f",
    "print": "".join(chr(i) for i in range(0x20, 0x7f)),
    "graph": "".join(chr(i) for i in range(0x21, 0x7f)),
    "blank": " \t",
    "ascii": "".join(chr(i) for i in range(0x80)),
}
# approximate unicode property categories (enough to keep the analysis useful)
_PROPERTY_RANGES = {
    "l": [(0x41, 0x5A), (0x61, 0x7A), (0xC0, 0x2AF), (0x370, 0x1FFF), (0x3040, 0x9FFF)],
    "letter": [(0x41, 0x5A), (0x61, 0x7A), (0xC0, 0x2AF), (0x370, 0x1FFF), (0x3040, 0x9FFF)],
    "alpha": [(0x41, 0x5A), (0x61, 0x7A), (0xC0, 0x2AF), (0x370, 0x1FFF), (0x3040, 0x9FFF)],
    "n": [(0x30, 0x39)],
    "nd": [(0x30, 0x39)],
    "digit": [(0x30, 0x39)],
    "z": [(0x20, 0x20), (0x09, 0x0D)],
    "zs": [(0x20, 0x20)],
    "space": [(0x09, 0x0D), (0x20, 0x20)],
}


# ---------------------------------------------------------------------------
# character sets as sorted, disjoint ranges
# ---------------------------------------------------------------------------

class CharSet:
    """Immutable set of code points represented as sorted disjoint ranges."""

    __slots__ = ("ranges",)

    def __init__(self, ranges: Sequence[Tuple[int, int]] = ()):
        self.ranges: Tuple[Tuple[int, int], ...] = _normalize(ranges)

    # -- constructors -------------------------------------------------------
    @classmethod
    def from_chars(cls, chars: Iterable[str]) -> "CharSet":
        return cls([(ord(c), ord(c)) for c in chars])

    @classmethod
    def any(cls) -> "CharSet":
        return cls([(0, MAX_CP)])

    @classmethod
    def of(cls, *pairs: Tuple[int, int]) -> "CharSet":
        return cls(pairs)

    # -- algebra ------------------------------------------------------------
    def union(self, other: "CharSet") -> "CharSet":
        return CharSet(self.ranges + other.ranges)

    def __or__(self, other: "CharSet") -> "CharSet":
        return self.union(other)

    def intersect(self, other: "CharSet") -> "CharSet":
        out: List[Tuple[int, int]] = []
        i = j = 0
        a, b = self.ranges, other.ranges
        while i < len(a) and j < len(b):
            lo = max(a[i][0], b[j][0])
            hi = min(a[i][1], b[j][1])
            if lo <= hi:
                out.append((lo, hi))
            if a[i][1] < b[j][1]:
                i += 1
            else:
                j += 1
        return CharSet(out)

    def __and__(self, other: "CharSet") -> "CharSet":
        return self.intersect(other)

    def subtract(self, other: "CharSet") -> "CharSet":
        return self.intersect(other.complement())

    def __sub__(self, other: "CharSet") -> "CharSet":
        return self.subtract(other)

    def complement(self) -> "CharSet":
        out: List[Tuple[int, int]] = []
        prev = 0
        for lo, hi in self.ranges:
            if lo > prev:
                out.append((prev, lo - 1))
            prev = max(prev, hi + 1)
        if prev <= MAX_CP:
            out.append((prev, MAX_CP))
        return CharSet(out)

    # -- queries ------------------------------------------------------------
    def __bool__(self) -> bool:
        return bool(self.ranges)

    def __len__(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.ranges)

    def contains(self, ch: str) -> bool:
        cp = ord(ch)
        for lo, hi in self.ranges:
            if lo <= cp <= hi:
                return True
            if cp < lo:
                return False
        return False

    def sample(self, limit: int = 6) -> List[str]:
        """Representative characters, preferring printable ASCII."""
        out: List[str] = []
        for ch in "a0_ x-/:@.,;ABC019=":
            if self.contains(ch) and ch not in out:
                out.append(ch)
            if len(out) >= limit:
                return out
        for cp in range(0x21, 0x7F):
            ch = chr(cp)
            if ch not in out and self.contains(ch):
                out.append(ch)
            if len(out) >= limit:
                return out
        for lo, hi in self.ranges:
            for cp in _interesting_points(lo, hi):
                ch = chr(cp)
                if ch not in out:
                    out.append(ch)
                if len(out) >= limit:
                    return out
        return out

    def first_char(self) -> Optional[str]:
        samples = self.sample(1)
        return samples[0] if samples else None

    def to_key(self) -> str:
        return ",".join(f"{lo:x}-{hi:x}" for lo, hi in self.ranges)

    def to_source(self) -> str:
        if not self.ranges:
            return "(?!)"
        if len(self) == 1:
            lo, _ = self.ranges[0]
            return _escape_char(chr(lo))
        parts: List[str] = []
        for lo, hi in self.ranges:
            if lo == hi:
                parts.append(_escape_char(chr(lo)))
            elif hi == lo + 1:
                parts.append(_escape_char(chr(lo)) + _escape_char(chr(hi)))
            else:
                parts.append(f"{_escape_char(chr(lo))}-{_escape_char(chr(hi))}")
        body = "".join(parts)
        return body if len(self) == 1 else f"[{body}]"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, CharSet) and self.ranges == other.ranges

    def __hash__(self) -> int:
        return hash(self.ranges)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CharSet({self.to_source()})"


def _interesting_points(lo: int, hi: int) -> List[int]:
    points: List[int] = []
    for cp in (lo, lo + 1, hi):
        if lo <= cp <= hi and cp not in points:
            points.append(cp)
    # prefer a printable ASCII representative when the range contains one
    for cp in (ord("a"), ord("0"), ord(" "), ord("_"), ord("A")):
        if lo <= cp <= hi and cp not in points:
            points.insert(0, cp)
            break
    return points


def _normalize(ranges: Sequence[Tuple[int, int]]) -> Tuple[Tuple[int, int], ...]:
    cleaned = [(max(0, lo), min(MAX_CP, hi)) for lo, hi in ranges if lo <= hi]
    cleaned.sort()
    merged: List[Tuple[int, int]] = []
    for lo, hi in cleaned:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


def _escape_char(ch: str) -> str:
    mapping = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\f": "\\f", "\v": "\\v",
               "\\": "\\\\", "]": "\\]", "^": "\\^", "-": "\\-", "[": "\\["}
    if ch in mapping:
        return mapping[ch]
    cp = ord(ch)
    if 0x20 <= cp <= 0x7E:
        return ch
    if cp <= 0xFF:
        return f"\\x{cp:02x}"
    return f"\\x{{{cp:x}}}"


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------

@dataclass
class Node:
    start: int = field(default=-1, compare=False)
    end: int = field(default=-1, compare=False)

    def children(self) -> List["Node"]:
        return []

    def to_source(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def walk(self) -> Iterator["Node"]:
        yield self
        for child in self.children():
            yield from child.walk()


@dataclass
class Empty(Node):
    def to_source(self) -> str:
        return ""


@dataclass
class Char(Node):
    chars: CharSet = field(default_factory=lambda: CharSet())
    display: Optional[str] = None

    def to_source(self) -> str:
        return self.chars.to_source()


@dataclass
class Seq(Node):
    items: List[Node] = field(default_factory=list)

    def children(self) -> List[Node]:
        return list(self.items)

    def to_source(self) -> str:
        return "".join(_group_source(item) for item in self.items)


@dataclass
class Alt(Node):
    options: List[Node] = field(default_factory=list)

    def children(self) -> List[Node]:
        return list(self.options)

    def to_source(self) -> str:
        return "(?:" + "|".join(opt.to_source() for opt in self.options) + ")"


@dataclass
class Repeat(Node):
    node: Optional[Node] = None
    min: int = 0
    max: Optional[int] = None          # None => unbounded
    lazy: bool = False
    possessive: bool = False

    def children(self) -> List[Node]:
        return [self.node] if self.node is not None else []

    @property
    def unbounded(self) -> bool:
        return self.max is None

    def to_source(self) -> str:
        body = _group_source(self.node) if self.node is not None else ""
        if self.min == 0 and self.max is None:
            quant = "*"
        elif self.min == 1 and self.max is None:
            quant = "+"
        elif self.min == 0 and self.max == 1:
            quant = "?"
        elif self.max is None:
            quant = "{%d,}" % self.min
        elif self.min == self.max:
            quant = "{%d}" % self.min
        else:
            quant = "{%d,%d}" % (self.min, self.max)
        if self.possessive:
            quant += "+"
        elif self.lazy:
            quant += "?"
        return body + quant


@dataclass
class Group(Node):
    node: Optional[Node] = None
    kind: str = "capturing"            # capturing|noncapturing|atomic|lookahead|lookbehind|
                                       # negative_lookahead|negative_lookbehind|flags|named
    index: Optional[int] = None
    name: Optional[str] = None
    flags: str = ""

    def children(self) -> List[Node]:
        return [self.node] if self.node is not None else []

    @property
    def zero_width(self) -> bool:
        return self.kind in ("lookahead", "lookbehind", "negative_lookahead",
                             "negative_lookbehind")

    def to_source(self) -> str:
        body = self.node.to_source() if self.node is not None else ""
        if self.kind == "noncapturing":
            return "(?:" + body + ")"
        if self.kind == "atomic":
            return "(?>" + body + ")"
        if self.kind == "lookahead":
            return "(?=" + body + ")"
        if self.kind == "negative_lookahead":
            return "(?!" + body + ")"
        if self.kind == "lookbehind":
            return "(?<=" + body + ")"
        if self.kind == "negative_lookbehind":
            return "(?<!" + body + ")"
        if self.kind == "flags":
            return "(?" + self.flags + ":" + body + ")"
        if self.kind == "named" and self.name:
            return "(?P<" + self.name + ">" + body + ")"
        return "(" + body + ")"


@dataclass
class Anchor(Node):
    kind: str = "bol"                  # bol|eol|bos|eos|eos_newline|word|non_word|sticky

    _CANON = {"bol": "^", "eol": "$", "bos": "\\A", "eos": "\\z",
              "eos_newline": "\\Z", "word": "\\b", "non_word": "\\B",
              "sticky": "\\G"}

    def to_source(self) -> str:
        return self._CANON.get(self.kind, "^")


@dataclass
class Backref(Node):
    ref: str = "1"
    index: Optional[int] = None

    def to_source(self) -> str:
        if self.index is not None:
            return "\\%d" % self.index
        return "\\k<" + self.ref + ">"


@dataclass
class Unsupported(Node):
    reason: str = ""
    raw: str = ""

    def to_source(self) -> str:
        return self.raw or "(?:)"


def _group_source(node: Optional[Node]) -> str:
    if node is None:
        return ""
    src = node.to_source()
    if isinstance(node, Seq) and len(node.items) > 1:
        return "(?:" + src + ")"
    if isinstance(node, Alt):
        return "(?:" + src + ")"
    return src


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

class RegexParseError(ValueError):
    pass


@dataclass
class ParseResult:
    ast: Node
    normalized: str
    flags: Set[str]
    notes: List[str] = field(default_factory=list)
    approx: bool = False
    unsupported: List[str] = field(default_factory=list)
    parse_error: Optional[str] = None


class RegexParser:
    def __init__(self, source: str, dialect: str = "python", flags: str = ""):
        self.src = source
        self.dialect = (dialect or "python").lower()
        self.i = 0
        self.n = len(source)
        self.flags: Set[str] = set(flags or "")
        self.global_flags: Set[str] = set(flags or "")
        self.group_count = 0
        self.named_groups: Dict[str, int] = {}
        self.notes: List[str] = []
        self.approx = False
        self.unsupported: List[str] = []

    # -- helpers ------------------------------------------------------------
    def _peek(self, offset: int = 0) -> str:
        pos = self.i + offset
        return self.src[pos] if pos < self.n else ""

    def _eof(self) -> bool:
        return self.i >= self.n

    def _skip_ignored(self) -> None:
        if "x" not in self.flags:
            return
        while not self._eof():
            ch = self.src[self.i]
            if ch in " \t\r\n\f\v":
                self.i += 1
            elif ch == "#":
                while not self._eof() and self.src[self.i] != "\n":
                    self.i += 1
            else:
                return

    def _note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)

    def _unsupported(self, reason: str, raw: str, start: int) -> Unsupported:
        self._note("construct not modelled: " + reason)
        if reason not in self.unsupported:
            self.unsupported.append(reason)
        return Unsupported(start=start, end=self.i, reason=reason, raw=raw)

    # -- entry point --------------------------------------------------------
    def parse(self) -> ParseResult:
        ast = self._parse_alt()
        if not self._eof():
            raise RegexParseError(f"unbalanced ')' at offset {self.i}")
        normalized = ast.to_source() if ast.to_source() else ""
        return ParseResult(
            ast=ast,
            normalized=normalized,
            flags=set(self.global_flags),
            notes=self.notes,
            approx=self.approx,
            unsupported=self.unsupported,
        )

    def _parse_alt(self) -> Node:
        start = self.i
        options = [self._parse_seq(stop="|)")]
        while self._peek() == "|":
            self.i += 1
            options.append(self._parse_seq(stop="|)"))
        if len(options) == 1:
            return options[0]
        return Alt(start=start, end=self.i, options=options)

    def _parse_seq(self, stop: str) -> Node:
        start = self.i
        items: List[Node] = []
        while not self._eof():
            self._skip_ignored()
            if self._eof():
                break
            if self._peek() in stop:
                break
            atom_start = self.i
            atom = self._parse_atom()
            if atom is None:
                continue
            atom = self._parse_quantifier(atom, atom_start)
            items.append(atom)
        if not items:
            return Empty(start=start, end=self.i)
        if len(items) == 1:
            return items[0]
        return Seq(start=start, end=self.i, items=items)

    # -- atoms --------------------------------------------------------------
    def _parse_atom(self) -> Optional[Node]:
        self._skip_ignored()
        if self._eof():
            return None
        ch = self.src[self.i]
        start = self.i
        if ch == "(":
            return self._parse_group()
        if ch == "[":
            return self._parse_class()
        if ch == "\\":
            return self._parse_escape(in_class=False)
        if ch == ".":
            self.i += 1
            if "s" in self.flags:
                chars = CharSet.any()
            else:
                chars = CharSet.any().subtract(CharSet.from_chars("\n"))
            return Char(chars=chars, start=start, end=self.i, display=".")
        if ch == "^":
            self.i += 1
            return Anchor(kind="bol", start=start, end=self.i)
        if ch == "$":
            self.i += 1
            return Anchor(kind="eol", start=start, end=self.i)
        if ch in "*+?":
            # dangling quantifier: treat as literal, matching permissive engines
            self.i += 1
            self._note("dangling quantifier treated as literal")
            return Char(chars=self._fold(CharSet.from_chars(ch)), start=start, end=self.i)
        if ch == "{":
            saved = self.i
            quant = self._try_parse_braces()
            if quant is not None:
                self.i = saved
                self._note("dangling brace quantifier treated as literal")
                self.i += 1
                return Char(chars=self._fold(CharSet.from_chars("{")), start=start, end=self.i)
        if ch == ")" and "(" not in self.src[:start]:
            self._note("unbalanced ')' treated as literal")
        self.i += 1
        return Char(chars=self._fold(CharSet.from_chars(ch)), start=start, end=self.i)

    def _fold(self, chars: CharSet) -> CharSet:
        if "i" not in self.flags:
            return chars
        extra: List[Tuple[int, int]] = []
        for lo, hi in chars.ranges:
            for cp in range(max(lo, 0x41), min(hi, 0x5A) + 1):
                extra.append((cp + 32, cp + 32))
            for cp in range(max(lo, 0x61), min(hi, 0x7A) + 1):
                extra.append((cp - 32, cp - 32))
        return CharSet(list(chars.ranges) + extra) if extra else chars

    # -- groups -------------------------------------------------------------
    def _parse_group(self) -> Node:
        start = self.i
        self.i += 1  # '('
        if self._peek() == "?":
            self.i += 1
            nxt = self._peek()
            if nxt == ":":
                self.i += 1
                body = self._parse_alt()
                self._expect(")")
                return Group(node=body, kind="noncapturing", start=start, end=self.i)
            if nxt == ">":
                self.i += 1
                body = self._parse_alt()
                self._expect(")")
                return Group(node=body, kind="atomic", start=start, end=self.i)
            if nxt in "=!":
                self.i += 1
                body = self._parse_alt()
                self._expect(")")
                kind = "lookahead" if nxt == "=" else "negative_lookahead"
                return Group(node=body, kind=kind, start=start, end=self.i)
            if nxt == "<":
                if self._peek(1) in "=!":
                    neg = self._peek(1) == "!"
                    self.i += 2
                    body = self._parse_alt()
                    self._expect(")")
                    kind = "negative_lookbehind" if neg else "lookbehind"
                    return Group(node=body, kind=kind, start=start, end=self.i)
                # named group (?<name>...)
                self.i += 1
                name = self._read_name(">")
                body = self._parse_alt()
                self._expect(")")
                self.group_count += 1
                self.named_groups[name] = self.group_count
                return Group(node=body, kind="named", name=name,
                             index=self.group_count, start=start, end=self.i)
            if nxt == "'":
                self.i += 1
                name = self._read_name("'")
                body = self._parse_alt()
                self._expect(")")
                self.group_count += 1
                self.named_groups[name] = self.group_count
                return Group(node=body, kind="named", name=name,
                             index=self.group_count, start=start, end=self.i)
            if nxt == "P":
                self.i += 1
                if self._peek() == "<":
                    self.i += 1
                    name = self._read_name(">")
                    body = self._parse_alt()
                    self._expect(")")
                    self.group_count += 1
                    self.named_groups[name] = self.group_count
                    return Group(node=body, kind="named", name=name,
                                 index=self.group_count, start=start, end=self.i)
                if self._peek() == "=":
                    self.i += 1
                    name = self._read_name(")")
                    idx = self.named_groups.get(name)
                    return Backref(ref=name, index=idx, start=start, end=self.i)
                return self._unsupported("(?P...)", self.src[start:self.i + 1], start)
            if nxt == "#":
                while not self._eof() and self.src[self.i] != ")":
                    self.i += 1
                self._expect(")")
                return Empty(start=start, end=self.i)
            if nxt == "(":
                # conditional (?(cond)yes|no)
                depth = 0
                while not self._eof():
                    ch = self.src[self.i]
                    self.i += 1
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            break
                return self._unsupported("conditional group", self.src[start:self.i], start)
            if nxt in "imxsauUJXD":
                # inline flags, either (?flags) or (?flags:...)
                flag_start = self.i
                while self._peek() and (self._peek().isalpha() or self._peek() == "-"):
                    self.i += 1
                flags = self.src[flag_start:self.i]
                if self._peek() == ")":
                    self.i += 1
                    self._apply_flags(flags)
                    return Empty(start=start, end=self.i)
                if self._peek() == ":":
                    self.i += 1
                    saved = set(self.flags)
                    self._apply_flags(flags)
                    body = self._parse_alt()
                    self._expect(")")
                    self.flags = saved
                    return Group(node=body, kind="flags", flags=flags,
                                 start=start, end=self.i)
                return self._unsupported("inline flags", self.src[start:self.i], start)
            if nxt in "R0123456789&":
                while not self._eof() and self.src[self.i] != ")":
                    self.i += 1
                self._expect(")")
                return self._unsupported("recursion/subroutine", self.src[start:self.i], start)
            if nxt == "~":
                while not self._eof() and self.src[self.i] != ")":
                    self.i += 1
                self._expect(")")
                return self._unsupported("absent operator", self.src[start:self.i], start)
            # unknown (?...) construct
            while not self._eof() and self.src[self.i] != ")":
                self.i += 1
            self._expect(")")
            return self._unsupported("unknown group construct", self.src[start:self.i], start)
        # plain capturing group
        body = self._parse_alt()
        self._expect(")")
        self.group_count += 1
        return Group(node=body, kind="capturing", index=self.group_count,
                     start=start, end=self.i)

    def _apply_flags(self, flags: str) -> None:
        negate = False
        for ch in flags:
            if ch == "-":
                negate = True
                continue
            if negate:
                self.flags.discard(ch)
            else:
                self.flags.add(ch)
                self.global_flags.add(ch)

    def _read_name(self, terminator: str) -> str:
        start = self.i
        while not self._eof() and self.src[self.i] != terminator:
            self.i += 1
        name = self.src[start:self.i]
        self._expect(terminator)
        return name

    def _expect(self, ch: str) -> None:
        if self._peek() != ch:
            raise RegexParseError(f"expected {ch!r} at offset {self.i}")
        self.i += 1

    # -- character classes --------------------------------------------------
    def _parse_class(self) -> Node:
        start = self.i
        self.i += 1  # '['
        negate = False
        if self._peek() == "^":
            negate = True
            self.i += 1
        chars = CharSet()
        first = True
        while not self._eof():
            ch = self.src[self.i]
            if ch == "]" and not first:
                self.i += 1
                break
            first = False
            if ch == "[" and self._peek(1) == ":":
                posix_end = self.src.find(":]", self.i + 2)
                if posix_end != -1:
                    name = self.src[self.i + 2:posix_end].lstrip("^")
                    inverted = self.src[self.i + 2:posix_end].startswith("^")
                    base = _POSIX.get(name.lower())
                    if base is None:
                        chars = chars.union(CharSet.any())
                        self._note(f"unknown POSIX class [[:{name}:]] approximated")
                        self.approx = True
                    else:
                        cs = CharSet.from_chars(base)
                        chars = chars.union(cs.complement() if inverted else cs)
                    self.i = posix_end + 2
                    continue
            lo_cs, single = self._class_item()
            if lo_cs is None:
                continue
            if single and self._peek() == "-" and self._peek(1) not in ("]", ""):
                self.i += 1
                hi_cs, hi_single = self._class_item()
                if hi_cs is not None and hi_single:
                    lo = min(ord(single), ord(hi_single))
                    hi = max(ord(single), ord(hi_single))
                    chars = chars.union(CharSet([(lo, hi)]))
                    continue
                if hi_cs is not None:
                    chars = chars.union(lo_cs).union(hi_cs)
                    continue
            chars = chars.union(lo_cs)
        if negate:
            chars = chars.complement()
        return Char(chars=self._fold(chars), start=start, end=self.i)

    def _class_item(self) -> Tuple[Optional[CharSet], Optional[str]]:
        """Return (charset, single-char-or-None) for one class element."""
        if self._eof():
            return None, None
        ch = self.src[self.i]
        if ch == "\\":
            result = self._parse_escape(in_class=True)
            if isinstance(result, Char):
                single = result.chars.first_char() if len(result.chars) == 1 else None
                return result.chars, single
            if isinstance(result, Anchor):  # \b inside class is backspace
                return CharSet.from_chars("\b"), "\b"
            return None, None
        self.i += 1
        return CharSet.from_chars(ch), ch

    # -- escapes ------------------------------------------------------------
    def _parse_escape(self, in_class: bool) -> Optional[Node]:
        start = self.i
        self.i += 1  # backslash
        if self._eof():
            return Char(chars=CharSet.from_chars("\\"), start=start, end=self.i)
        ch = self.src[self.i]
        self.i += 1
        simple = {
            "d": CharSet.from_chars(DIGITS),
            "w": CharSet.from_chars(WORD),
            "s": CharSet.from_chars(SPACE),
            "h": CharSet([(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)]),
            "v": CharSet([(0x0A, 0x0D), (0x85, 0x85), (0x2028, 0x2029)]),
        }
        if ch in "dws":
            return Char(chars=self._fold(simple[ch]), start=start, end=self.i)
        if ch in "DWS":
            if ch.lower() == "d":
                base = simple["d"]
            elif ch.lower() == "w":
                base = simple["w"]
            else:
                base = simple["s"]
            return Char(chars=self._fold(base.complement()), start=start, end=self.i)
        if ch in "H":
            return Char(chars=self._fold(simple["h"].complement()), start=start, end=self.i)
        if ch in "V":
            return Char(chars=self._fold(simple["v"].complement()), start=start, end=self.i)
        if ch == "R":
            return Char(chars=CharSet.from_chars("\n\r\x0b\x0c\x85\u2028\u2029"),
                        start=start, end=self.i)
        if ch == "X":
            self._note("\\X grapheme cluster approximated as any character")
            self.approx = True
            return Char(chars=CharSet.any(), start=start, end=self.i)
        if ch == "N" and self._peek() != "{":
            return Char(chars=CharSet.any().subtract(CharSet.from_chars("\n")),
                        start=start, end=self.i)
        if ch == "N" and self._peek() == "{":
            self._note("\\N{...} approximated as any character")
            self.approx = True
            while not self._eof() and self.src[self.i] != "}":
                self.i += 1
            self._expect("}")
            return Char(chars=CharSet.any(), start=start, end=self.i)
        if ch in "pP":
            self.approx = True
            negated = ch == "P"
            name = ""
            if self._peek() == "{":
                close = self.src.find("}", self.i)
                if close == -1:
                    return Char(chars=CharSet.any(), start=start, end=self.i)
                name = self.src[self.i + 1:close]
                self.i = close + 1
            else:
                name = self._peek()
                self.i += 1
            key = name.strip("^").lower().split("=")[-1]
            ranges: List[Tuple[int, int]] = []
            for part in key.split("|"):
                ranges.extend(_PROPERTY_RANGES.get(part, []))
            if not ranges:
                ranges = [(0, MAX_CP)]
                self._note(f"unicode property \\p{{{name}}} approximated as any character")
            cs = CharSet(ranges)
            return Char(chars=self._fold(cs.complement() if negated else cs),
                        start=start, end=self.i)
        if ch == "Q":
            # \Q...\E literal run (PCRE)
            end = self.src.find("\\E", self.i)
            literal = self.src[self.i:end] if end != -1 else self.src[self.i:]
            self.i = (end + 2) if end != -1 else self.n
            items = [Char(chars=self._fold(CharSet.from_chars(c)),
                          start=start, end=self.i) for c in literal]
            return Seq(start=start, end=self.i, items=items)
        if ch in "AZzG":
            kind = {"A": "bos", "Z": "eos_newline", "z": "eos", "G": "sticky"}[ch]
            return Anchor(kind=kind, start=start, end=self.i)
        if ch in "bB":
            if in_class:
                if ch == "b":
                    return Char(chars=CharSet.from_chars("\b"), start=start, end=self.i)
                return Char(chars=CharSet.from_chars("B"), start=start, end=self.i)
            return Anchor(kind="word" if ch == "b" else "non_word",
                          start=start, end=self.i)
        if ch == "K":
            self._note("\\K reset operator treated as zero-width")
            return Empty(start=start, end=self.i)
        if ch in _ESCAPE_CHARS:
            return Char(chars=self._fold(CharSet.from_chars(_ESCAPE_CHARS[ch])),
                        start=start, end=self.i)
        if ch == "x":
            return self._hex_escape(start)
        if ch == "u":
            return self._unicode_escape(start)
        if ch == "c":
            if self._eof():
                return Char(chars=CharSet.from_chars("\\c"), start=start, end=self.i)
            ctrl = chr(ord(self.src[self.i]) % 32)
            self.i += 1
            return Char(chars=CharSet.from_chars(ctrl), start=start, end=self.i)
        if ch == "0":
            # Octal escape: \0 followed by up to two *octal* digits.  Ruby
            # treats \08 as NUL followed by "8", not as an invalid octal 8.
            digits = "0"
            while self._peek() in "01234567" and len(digits) < 3:
                digits += self._peek()
                self.i += 1
            return Char(chars=CharSet.from_chars(chr(int(digits, 8))),
                        start=start, end=self.i)
        if ch.isdigit():
            digits = ch
            while self._peek().isdigit() and len(digits) < 3:
                digits += self._peek()
                self.i += 1
            if len(digits) == 3 and all(c in "01234567" for c in digits):
                return Char(chars=CharSet.from_chars(chr(int(digits, 8))),
                            start=start, end=self.i)
            # One/two digits are a backreference; a three-digit sequence that
            # is not valid octal (\999) is engine-specific.  Treat it as a
            # backreference instead of crashing the parser.
            index = int(digits)
            return Backref(ref=str(index), index=index, start=start, end=self.i)
        if ch == "k" and self._peek() in "<'":
            opener = self._peek()
            closer = ">" if opener == "<" else "'"
            end = self.src.find(closer, self.i + 1)
            if end == -1:
                self.i += 1
                return self._unsupported("malformed named backreference", "\\k", start)
            name = self.src[self.i + 1:end]
            self.i = end + 1
            return Backref(ref=name, index=self.named_groups.get(name), start=start, end=self.i)
        if ch == "g" and self._peek() in "<'{-":
            # PCRE/Ruby subroutine or backreference: \g<1>, \g'1', \g{-1}
            opener = self._peek()
            closer = {"<": ">", "'": "'", "{": "}"}[opener]
            end = self.src.find(closer, self.i + 1)
            body = self.src[self.i + 1:end] if end != -1 else ""
            self.i = (end + 1) if end != -1 else self.n
            if body.lstrip("-").isdigit():
                try:
                    idx = int(body)
                except ValueError:
                    idx = None
                return Backref(ref=body, index=idx, start=start, end=self.i)
            if body.lstrip("+-").isdigit():
                return self._unsupported("relative subroutine call", self.src[start:self.i], start)
            return Backref(ref=body, index=self.named_groups.get(body),
                           start=start, end=self.i)
        # identity escape (e.g. \. \- \/ \{)
        return Char(chars=self._fold(CharSet.from_chars(ch)), start=start, end=self.i)

    def _hex_escape(self, start: int) -> Node:
        if self._peek() == "{":
            end = self.src.find("}", self.i)
            body = self.src[self.i + 1:end] if end != -1 else ""
            self.i = (end + 1) if end != -1 else self.n
            try:
                value = int(body, 16)
            except ValueError:
                value = 0xFFFD
            return Char(chars=CharSet.from_chars(chr(min(value, MAX_CP))),
                        start=start, end=self.i)
        digits = self.src[self.i:self.i + 2]
        self.i += len(digits)
        try:
            value = int(digits, 16) if digits else 0
        except ValueError:
            value = ord("x")
        return Char(chars=self._fold(CharSet.from_chars(chr(value))),
                    start=start, end=self.i)

    def _unicode_escape(self, start: int) -> Node:
        if self._peek() == "{":
            end = self.src.find("}", self.i)
            body = self.src[self.i + 1:end] if end != -1 else ""
            self.i = (end + 1) if end != -1 else self.n
            try:
                value = int(body, 16)
            except ValueError:
                value = 0xFFFD
            return Char(chars=CharSet.from_chars(chr(min(value, MAX_CP))),
                        start=start, end=self.i)
        digits = self.src[self.i:self.i + 4]
        self.i += len(digits)
        try:
            value = int(digits, 16) if digits else 0
        except ValueError:
            value = ord("u")
        return Char(chars=self._fold(CharSet.from_chars(chr(min(value, MAX_CP)))),
                    start=start, end=self.i)

    # -- quantifiers --------------------------------------------------------
    def _try_parse_braces(self) -> Optional[Tuple[int, Optional[int]]]:
        """Parse ``{n}``, ``{n,}``, ``{n,m}`` at current position."""
        assert self._peek() == "{"
        i = self.i + 1
        num_start = i
        while i < self.n and self.src[i].isdigit():
            i += 1
        if i == num_start:
            return None
        low = int(self.src[num_start:i])
        if i < self.n and self.src[i] == "}":
            self.i = i + 1
            return low, low
        if i < self.n and self.src[i] == ",":
            i += 1
            hi_start = i
            while i < self.n and self.src[i].isdigit():
                i += 1
            if i < self.n and self.src[i] == "}":
                high = int(self.src[hi_start:i]) if i > hi_start else None
                self.i = i + 1
                return low, high
        return None

    def _parse_quantifier(self, atom: Node, atom_start: int) -> Node:
        self._skip_ignored()
        if self._eof():
            return atom
        ch = self._peek()
        low: Optional[int] = None
        high: Optional[int] = None
        if ch == "*":
            low, high = 0, None
            self.i += 1
        elif ch == "+":
            low, high = 1, None
            self.i += 1
        elif ch == "?":
            low, high = 0, 1
            self.i += 1
        elif ch == "{":
            quant = self._try_parse_braces()
            if quant is None:
                return atom
            low, high = quant
        else:
            return atom
        if high is not None and low is not None and low > high:
            raise RegexParseError(
                f"numbers out of order in quantifier at offset {atom_start}: "
                f"{{{low},{high}}}"
            )
        lazy = False
        possessive = False
        if self._peek() == "?":
            lazy = True
            self.i += 1
        elif self._peek() == "+" and self.dialect in ("php", "ruby", "python"):
            possessive = True
            self.i += 1
        return Repeat(node=atom, min=low or 0, max=high, lazy=lazy,
                      possessive=possessive, start=atom_start, end=self.i)


def parse(pattern: str, dialect: str = "python", flags: str = "") -> ParseResult:
    return RegexParser(pattern, dialect=dialect, flags=flags).parse()


# ---------------------------------------------------------------------------
# static metrics over the AST
# ---------------------------------------------------------------------------

def nullable(node: Optional[Node]) -> bool:
    if node is None:
        return True
    if isinstance(node, Empty):
        return True
    if isinstance(node, Char):
        return False
    if isinstance(node, Anchor):
        return True
    if isinstance(node, Backref):
        # a backreference normally consumes at least one character; treating it
        # as nullable would create false "empty loop" conclusions
        return False
    if isinstance(node, Unsupported):
        return True
    if isinstance(node, Seq):
        return all(nullable(item) for item in node.items)
    if isinstance(node, Alt):
        return any(nullable(opt) for opt in node.options)
    if isinstance(node, Repeat):
        return node.min == 0 or nullable(node.node)
    if isinstance(node, Group):
        if node.zero_width:
            return True
        return nullable(node.node)
    return True


def min_len(node: Optional[Node]) -> int:
    if node is None:
        return 0
    if isinstance(node, (Empty, Anchor)):
        return 0
    if isinstance(node, Char):
        return 1
    if isinstance(node, (Backref, Unsupported)):
        return 0
    if isinstance(node, Seq):
        return sum(min_len(item) for item in node.items)
    if isinstance(node, Alt):
        return min((min_len(opt) for opt in node.options), default=0)
    if isinstance(node, Repeat):
        return (node.min or 0) * min_len(node.node)
    if isinstance(node, Group):
        return 0 if node.zero_width else min_len(node.node)
    return 0


def max_len(node: Optional[Node]) -> Optional[int]:
    if node is None:
        return 0
    if isinstance(node, (Empty, Anchor)):
        return 0
    if isinstance(node, Char):
        return 1
    if isinstance(node, (Backref, Unsupported)):
        return None
    if isinstance(node, Seq):
        total = 0
        for item in node.items:
            part = max_len(item)
            if part is None:
                return None
            total += part
        return total
    if isinstance(node, Alt):
        values = [max_len(opt) for opt in node.options]
        return None if any(v is None for v in values) else max(values, default=0)
    if isinstance(node, Repeat):
        inner = max_len(node.node)
        if node.max is None or inner is None:
            return None
        return node.max * inner
    if isinstance(node, Group):
        return 0 if node.zero_width else max_len(node.node)
    return None


def first_chars(node: Optional[Node]) -> CharSet:
    if node is None:
        return CharSet()
    if isinstance(node, Char):
        return node.chars
    if isinstance(node, (Empty, Anchor)):
        return CharSet()
    if isinstance(node, (Backref, Unsupported)):
        return CharSet.any()
    if isinstance(node, Char):
        return node.chars
    if isinstance(node, Seq):
        out = CharSet()
        for item in node.items:
            out = out.union(first_chars(item))
            if not nullable(item):
                break
        return out
    if isinstance(node, Alt):
        out = CharSet()
        for opt in node.options:
            out = out.union(first_chars(opt))
        return out
    if isinstance(node, Repeat):
        return first_chars(node.node)
    if isinstance(node, Group):
        return CharSet() if node.zero_width else first_chars(node.node)
    return CharSet()


def last_chars(node: Optional[Node]) -> CharSet:
    if node is None:
        return CharSet()
    if isinstance(node, Char):
        return node.chars
    if isinstance(node, (Empty, Anchor)):
        return CharSet()
    if isinstance(node, (Backref, Unsupported)):
        return CharSet.any()
    if isinstance(node, Seq):
        out = CharSet()
        for item in reversed(node.items):
            out = out.union(last_chars(item))
            if not nullable(item):
                break
        return out
    if isinstance(node, Alt):
        out = CharSet()
        for opt in node.options:
            out = out.union(last_chars(opt))
        return out
    if isinstance(node, Repeat):
        return last_chars(node.node)
    if isinstance(node, Group):
        return CharSet() if node.zero_width else last_chars(node.node)
    return CharSet()


def all_chars(node: Optional[Node]) -> CharSet:
    out = CharSet()
    for sub in (node.walk() if node is not None else []):
        if isinstance(sub, Char):
            out = out.union(sub.chars)
    return out


def contains_unbounded_repeat(node: Optional[Node]) -> bool:
    if node is None:
        return False
    for sub in node.walk():
        if isinstance(sub, Repeat) and sub.max is None and not sub.possessive:
            return True
    return False


def shortest_sample(node: Optional[Node], limit: int = 24) -> str:
    """Shortest-ish concrete string accepted by the node (for attack prefixes)."""
    if node is None:
        return ""
    if isinstance(node, (Empty, Anchor)):
        return ""
    if isinstance(node, Char):
        sample = node.chars.first_char()
        return sample or ""
    if isinstance(node, Backref):
        return ""
    if isinstance(node, Unsupported):
        return ""
    if isinstance(node, Seq):
        out = ""
        for item in node.items:
            out += shortest_sample(item)
            if len(out) >= limit:
                break
        return out[:limit]
    if isinstance(node, Alt):
        best = None
        for opt in node.options:
            sample = shortest_sample(opt)
            if best is None or len(sample) < len(best):
                best = sample
        return best or ""
    if isinstance(node, Repeat):
        count = node.min or 0
        if count == 0 and node.node is not None and not nullable(node.node):
            # prefer one repetition for a more realistic prefix
            count = 1
        return (shortest_sample(node.node) * count)[:limit]
    if isinstance(node, Group):
        return "" if node.zero_width else shortest_sample(node.node)
    return ""


def iter_repeats(node: Optional[Node], path: Optional[List[Node]] = None) -> Iterator[Tuple[Repeat, List[Node]]]:
    path = path or []
    if node is None:
        return
    if isinstance(node, Repeat):
        yield node, path
        yield from iter_repeats(node.node, path + [node])
        return
    for child in node.children():
        yield from iter_repeats(child, path + [node])


def find_node_path(root: Node, target: Node) -> Optional[List[Node]]:
    """Path from root to target (inclusive), following ``children`` order."""
    if root is target:
        return [root]
    for child in root.children():
        sub = find_node_path(child, target)
        if sub is not None:
            return [root] + sub
    return None


def prefix_before(root: Node, target: Node) -> str:
    """Concrete prefix matching everything before ``target`` in AST order."""
    path = find_node_path(root, target)
    if not path:
        return ""
    parts: List[str] = []
    cursor = target
    for parent in reversed(path[:-1]):
        if isinstance(parent, Seq):
            for item in parent.items:
                if item is cursor:
                    break
                parts.append(shortest_sample(item))
        elif isinstance(parent, Repeat):
            count = parent.min or 0
            parts.extend([shortest_sample(parent.node)] * count)
        elif isinstance(parent, Alt):
            parts.append(shortest_sample(parent.options[0]) if parent.options else "")
        elif isinstance(parent, Group):
            continue
        cursor = parent
    return "".join(parts)


def suffix_after(root: Node, target: Node) -> str:
    path = find_node_path(root, target)
    if not path:
        return ""
    parts: List[str] = []
    cursor = target
    for parent in reversed(path[:-1]):
        if isinstance(parent, Seq):
            seen = False
            for item in parent.items:
                if item is cursor:
                    seen = True
                    continue
                if seen:
                    parts.append(shortest_sample(item))
        elif isinstance(parent, Repeat):
            remaining = max((parent.min or 0) - 1, 0)
            parts.extend([shortest_sample(parent.node)] * remaining)
        cursor = parent
    return "".join(parts)
