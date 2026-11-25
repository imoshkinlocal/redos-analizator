"""Python regexp extraction based on the standard :mod:`ast` module.

Coverage (deliberately broader than a naive ``re.match("literal", ...)`` scan):

* ``re`` / ``regex`` with import aliases and ``from ... import ... as ...``;
* module level variables, local variables, ``self.attr`` attributes;
* implicit and explicit concatenation, f-strings without placeholders,
  ``"".join``, ``.format`` with constant arguments;
* pre-compiled objects (``P = re.compile(...); P.search(x)``);
* user wrappers that forward a parameter into a regexp sink (one call level,
  resolved transitively up to a small depth);
* unresolved values become ``dynamic_pattern_unresolved`` findings instead of
  being silently dropped;
* a light, evidence-backed classification of the data expression
  (``input_control``), without pretending to be a full data-flow analysis.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ..models import InputControl, RegexCandidate, SourceType
from .base import classify_input_control, make_candidate

EXTRACTOR_NAME = "python-ast"

# sink -> (pattern argument index, data argument index or None)
SINKS: Dict[str, Tuple[int, Optional[int]]] = {
    "compile": (0, None),
    "match": (0, 1),
    "search": (0, 1),
    "fullmatch": (0, 1),
    "findall": (0, 1),
    "finditer": (0, 1),
    "sub": (0, 2),
    "subn": (0, 2),
    "split": (0, 1),
}

FLAG_BITS = {
    "IGNORECASE": "i", "I": "i",
    "MULTILINE": "m", "M": "m",
    "DOTALL": "s", "S": "s",
    "VERBOSE": "x", "X": "x",
    "ASCII": "a", "A": "a",
    "UNICODE": "u", "U": "u",
    "LOCALE": "l", "L": "l",
}
FLAG_VALUES = {"i": 2, "l": 4, "m": 8, "s": 16, "u": 32, "x": 64, "a": 256}
BIT_TO_FLAG = {2: "i", 4: "l", 8: "m", 16: "s", 32: "u", 64: "x", 256: "a"}

MAX_WRAPPER_DEPTH = 3


@dataclass
class ConstValue:
    value: Optional[str]
    source_type: str = SourceType.LITERAL.value
    confidence: float = 1.0
    notes: List[str] = field(default_factory=list)
    expr: str = ""

    @property
    def resolved(self) -> bool:
        return self.value is not None


def _unparse(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - very old/invalid trees
        return ""


class PythonExtractor:
    def __init__(self, package: str, version: str, rel_path: str, source: str):
        self.package = package
        self.version = version
        self.rel_path = rel_path
        self.source = source
        self.candidates: List[RegexCandidate] = []
        self.notes: List[str] = []
        self.import_aliases: Dict[str, str] = {}       # alias -> re | regex
        self.function_aliases: Dict[str, Tuple[str, str]] = {}  # local name -> (module, sink)
        self.module_env: Dict[str, ast.AST] = {}
        self.module_reassignments: Set[str] = set()
        self.compiled_vars: Dict[str, Tuple[ast.AST, ast.AST]] = {}
        self.wrapper_params: Dict[str, Dict[int, str]] = {}

    # -- public -------------------------------------------------------------
    def extract(self) -> List[RegexCandidate]:
        try:
            tree = ast.parse(self.source, filename=self.rel_path)
        except SyntaxError:
            return []
        except (ValueError, RecursionError):
            return []

        self._collect_imports(tree)
        self._collect_module_env(tree)
        self._collect_compiled_vars(tree)
        self._collect_wrappers(tree)
        self.env_cache = self._build_env_cache(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._handle_call(node, tree)
        return self.candidates

    def _build_env_cache(self, tree: ast.AST) -> Dict[int, Dict[str, ast.AST]]:
        """Map every call node to the single-assignment locals of its scope."""
        cache: Dict[int, Dict[str, ast.AST]] = {}
        scopes: List[ast.AST] = [tree]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                scopes.append(node)
        for scope in scopes:
            env = self._scope_env(scope)
            for node in ast.walk(scope):
                if isinstance(node, ast.Call) and id(node) not in cache:
                    cache[id(node)] = env
        return cache

    def _scope_env(self, scope: ast.AST) -> Dict[str, ast.AST]:
        counts: Dict[str, int] = {}
        env: Dict[str, ast.AST] = {}
        for node in ast.walk(scope):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = node.value
                if value is None:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    name = self._target_name(target)
                    if not name:
                        continue
                    counts[name] = counts.get(name, 0) + 1
                    if counts[name] == 1:
                        env[name] = value
                    else:
                        env.pop(name, None)
        return env

    # -- imports ------------------------------------------------------------
    def _collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("re", "regex"):
                        self.import_aliases[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module in ("re", "regex"):
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.function_aliases[local] = (node.module, alias.name)

    # -- environments -------------------------------------------------------
    def _collect_module_env(self, tree: ast.Module) -> None:
        counts: Dict[str, int] = {}
        for node in tree.body:
            targets: List[ast.AST] = []
            value: Optional[ast.AST] = None
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
                value = node.value
            for target in targets:
                if isinstance(target, ast.Name):
                    counts[target.id] = counts.get(target.id, 0) + 1
                    if counts[target.id] == 1 and value is not None:
                        self.module_env[target.id] = value
                    elif counts[target.id] > 1:
                        self.module_reassignments.add(target.id)
        for name in self.module_reassignments:
            self.module_env.pop(name, None)

    def _collect_compiled_vars(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            sink = self._resolve_sink(value.func)
            if not sink or sink[1] != "compile":
                continue
            args = value.args
            if not args:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            flags_node = args[1] if len(args) > 1 else None
            for target in targets:
                name = self._target_name(target)
                if name:
                    self.compiled_vars[name] = (args[0], flags_node)  # type: ignore[assignment]

    @staticmethod
    def _target_name(target: ast.AST) -> Optional[str]:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return "self." + target.attr if isinstance(target.value, ast.Name) and target.value.id == "self" else None
        return None

    # -- wrapper discovery --------------------------------------------------
    def _collect_wrappers(self, tree: ast.AST) -> None:
        functions: Dict[str, ast.FunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[node.name] = node  # type: ignore[assignment]
        changed = True
        iterations = 0
        while changed and iterations < MAX_WRAPPER_DEPTH + 1:
            changed = False
            iterations += 1
            for name, func in functions.items():
                params = [arg.arg for arg in func.args.args]
                mapping: Dict[int, str] = dict(self.wrapper_params.get(name, {}))
                for node in ast.walk(func):
                    if not isinstance(node, ast.Call):
                        continue
                    sink = self._resolve_sink(node.func)
                    if sink:
                        pattern_index, _ = SINKS[sink[1]]
                        if pattern_index < len(node.args):
                            arg = node.args[pattern_index]
                            if isinstance(arg, ast.Name) and arg.id in params:
                                mapping[pattern_index] = sink[1]
                    else:
                        wrapper_name = self._call_name(node.func)
                        known = self.wrapper_params.get(wrapper_name or "")
                        if known:
                            for param_index, sink_name in known.items():
                                if param_index < len(node.args):
                                    arg = node.args[param_index]
                                    if isinstance(arg, ast.Name) and arg.id in params:
                                        mapping[param_index] = sink_name
                if mapping != self.wrapper_params.get(name, {}):
                    self.wrapper_params[name] = mapping
                    changed = True

    # -- name resolution ----------------------------------------------------
    def _resolve_sink(self, func: ast.AST) -> Optional[Tuple[str, str]]:
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = self.import_aliases.get(func.value.id)
            if module and func.attr in SINKS:
                return module, func.attr
            if func.attr in SINKS and func.value.id in self.compiled_vars:
                return "compiled", func.attr
        if isinstance(func, ast.Name):
            if func.id in self.function_aliases:
                module, sink = self.function_aliases[func.id]
                if sink in SINKS:
                    return module, sink
        return None

    def _call_name(self, func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    # -- constant folding ---------------------------------------------------
    def _local_env(self, tree: ast.AST, call: ast.Call) -> Dict[str, ast.AST]:
        return getattr(self, "env_cache", {}).get(id(call), {})

    def _resolve(self, node: Optional[ast.AST], env: Dict[str, ast.AST],
                 depth: int = 0) -> ConstValue:
        if node is None:
            return ConstValue(None, SourceType.DYNAMIC.value, 0.0, ["missing argument"])
        if depth > 6:
            return ConstValue(None, SourceType.DYNAMIC.value, 0.0, ["resolution depth limit"])
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return ConstValue(node.value, SourceType.LITERAL.value, 1.0, [], _unparse(node))
            if isinstance(node.value, bytes):
                try:
                    return ConstValue(node.value.decode("utf-8"), SourceType.LITERAL.value,
                                      0.9, ["bytes literal decoded as utf-8"], _unparse(node))
                except UnicodeDecodeError:
                    return ConstValue(None, SourceType.DYNAMIC.value, 0.0,
                                      ["non-utf8 bytes literal"], _unparse(node))
            return ConstValue(None, SourceType.DYNAMIC.value, 0.0,
                              ["pattern is not a string"], _unparse(node))
        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Constant):
                    parts.append(str(value.value.value))
                else:
                    return ConstValue(None, SourceType.DYNAMIC.value, 0.2,
                                      ["f-string contains a runtime value"], _unparse(node))
            return ConstValue("".join(parts), SourceType.CONCAT.value, 0.95,
                              ["f-string folded to a literal"], _unparse(node))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve(node.left, env, depth + 1)
            right = self._resolve(node.right, env, depth + 1)
            if left.resolved and right.resolved:
                source = (SourceType.LITERAL.value
                          if left.source_type == right.source_type == SourceType.LITERAL.value
                          else SourceType.CONCAT.value)
                return ConstValue(left.value + right.value, source,
                                  min(left.confidence, right.confidence, 0.95),
                                  left.notes + right.notes, _unparse(node))
            return ConstValue(None, SourceType.DYNAMIC.value, 0.2,
                              ["string concatenation with an unresolved part"], _unparse(node))
        if isinstance(node, ast.Name):
            if node.id in env:
                resolved = self._resolve(env[node.id], env, depth + 1)
                if resolved.resolved:
                    resolved.source_type = SourceType.VARIABLE.value
                    resolved.notes = resolved.notes + [f"resolved variable {node.id}"]
                    return resolved
            if node.id in self.module_env:
                resolved = self._resolve(self.module_env[node.id], {}, depth + 1)
                if resolved.resolved:
                    resolved.source_type = SourceType.VARIABLE.value
                    resolved.notes = resolved.notes + [f"resolved module variable {node.id}"]
                    return resolved
            return ConstValue(None, SourceType.DYNAMIC.value, 0.2,
                              [f"unresolved variable {node.id}"], node.id)
        if isinstance(node, ast.Attribute):
            name = self._target_name(node)
            if name and name in self.compiled_vars:
                pattern_node, _ = self.compiled_vars[name]
                return self._resolve(pattern_node, env, depth + 1)
            return ConstValue(None, SourceType.DYNAMIC.value, 0.2,
                              [f"attribute value {_unparse(node)} is not resolvable"],
                              _unparse(node))
        if isinstance(node, ast.Call):
            func_name = self._call_name(node.func) or ""
            if func_name == "join" and node.args:
                receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
                if isinstance(receiver, ast.Constant) and isinstance(receiver.value, str):
                    parts: List[str] = []
                    for arg in node.args:
                        values = arg.elts if isinstance(arg, (ast.List, ast.Tuple)) else [arg]
                        for item in values:
                            piece = self._resolve(item, env, depth + 1)
                            if not piece.resolved:
                                return ConstValue(None, SourceType.DYNAMIC.value, 0.2,
                                                  ["join() over an unresolved value"], _unparse(node))
                            parts.append(piece.value or "")
                    return ConstValue(receiver.value.join(parts), SourceType.CONCAT.value, 0.9,
                                      [], _unparse(node))
            if func_name in ("format", "dedent", "strip", "encode", "decode", "str") and node.args:
                inner = self._resolve(node.args[0], env, depth + 1)
                if inner.resolved:
                    return inner
            return ConstValue(None, SourceType.DYNAMIC.value, 0.3,
                              [f"call to {func_name}() is not resolvable"], _unparse(node))
        if isinstance(node, ast.IfExp):
            left = self._resolve(node.body, env, depth + 1)
            right = self._resolve(node.orelse, env, depth + 1)
            if left.resolved and right.resolved and left.value == right.value:
                return left
            return ConstValue(None, SourceType.DYNAMIC.value, 0.2,
                              ["conditional expression with different branches"], _unparse(node))
        if isinstance(node, (ast.Subscript, ast.Dict, ast.List, ast.Tuple, ast.Await)):
            return ConstValue(None, SourceType.DYNAMIC.value, 0.2,
                              ["value depends on runtime data"], _unparse(node))
        return ConstValue(None, SourceType.DYNAMIC.value, 0.1,
                          [f"unsupported expression {type(node).__name__}"], _unparse(node))

    def _resolve_flags(self, node: Optional[ast.AST], env: Dict[str, ast.AST]) -> Tuple[str, List[str]]:
        if node is None:
            return "", []
        notes: List[str] = []
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            flags = "".join(sorted(flag for bit, flag in BIT_TO_FLAG.items() if node.value & bit))
            leftover = node.value & ~sum(BIT_TO_FLAG)
            if leftover:
                notes.append(f"unknown flag bits: {leftover}")
            return flags, notes
        if isinstance(node, ast.Attribute):
            module = None
            if isinstance(node.value, ast.Name):
                module = self.import_aliases.get(node.value.id)
            if module:
                flag = FLAG_BITS.get(node.attr)
                if flag:
                    return flag, notes
            return "", [f"unknown flag attribute {_unparse(node)}"]
        if isinstance(node, ast.Name):
            if node.id in env:
                return self._resolve_flags(env[node.id], env)
            flag = FLAG_BITS.get(node.id)
            if flag:
                return flag, notes
            return "", [f"unresolved flags variable {node.id}"]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left, left_notes = self._resolve_flags(node.left, env)
            right, right_notes = self._resolve_flags(node.right, env)
            return "".join(sorted(set(left + right))), left_notes + right_notes
        return "", [f"flags value {_unparse(node)} is not resolvable"]

    # -- call handling ------------------------------------------------------
    def _handle_call(self, call: ast.Call, tree: ast.AST) -> None:
        env = self._local_env(tree, call)
        sink = self._resolve_sink(call.func)
        if sink:
            self._emit_sink(call, sink, env)
            return
        wrapper_name = self._call_name(call.func)
        if wrapper_name and wrapper_name in self.wrapper_params:
            self._emit_wrapper(call, wrapper_name, env)
            return
        # re.compile(...).match(x) chain
        if isinstance(call.func, ast.Attribute):
            inner = call.func.value
            if isinstance(inner, ast.Call):
                inner_sink = self._resolve_sink(inner.func)
                if inner_sink and inner_sink[1] == "compile" and call.func.attr in SINKS:
                    self._emit_sink(inner, inner_sink, env, chain_attr=call.func.attr,
                                    data_args=call.args)

    def _emit_sink(self, call: ast.Call, sink: Tuple[str, str], env: Dict[str, ast.AST],
                   chain_attr: Optional[str] = None,
                   data_args: Sequence[ast.AST] = ()) -> None:
        module, name = sink

        # A pre-compiled object used later: the pattern lives in the variable,
        # the first argument is the data.
        if module == "compiled":
            receiver = self._target_name(call.func.value) if isinstance(call.func, ast.Attribute) else None
            entry = self.compiled_vars.get(receiver or "")
            if entry is None:
                return
            pattern_node, flags_node = entry
            flags, flag_notes = self._resolve_flags(flags_node, env)
            data_node = call.args[0] if call.args else None
            self._emit(pattern_node, f"<compiled {receiver}>.{name}", "compiled",
                       data_node, env, flags, flag_notes)
            return

        # re.compile(pattern).match(text): pattern and flags come from compile()
        if chain_attr is not None:
            pattern_node = call.args[0] if call.args else None
            flags, flag_notes = "", []
            if len(call.args) > 1:
                flags, flag_notes = self._resolve_flags(call.args[1], env)
            data_node = data_args[0] if data_args else None
            self._emit(pattern_node, f"{module}.compile().{chain_attr}", module, data_node,
                       env, flags, flag_notes,
                       notes=["compiled pattern used through a chained call"],
                       engine_hint="regex" if module == "regex" else None)
            return

        args = list(call.args)
        pattern_index, data_index = SINKS[name]
        if pattern_index >= len(args):
            return
        pattern_node = args[pattern_index]
        data_node = args[data_index] if data_index is not None and data_index < len(args) else None
        flags, flag_notes = "", []
        if name == "compile" and len(args) > 1:
            flags, flag_notes = self._resolve_flags(args[1], env)
        flags, kw_notes = self._extract_keyword_flags(call, env, flags)
        flag_notes.extend(kw_notes)
        self._emit(pattern_node, f"{module}.{name}", module, data_node, env, flags,
                   flag_notes, engine_hint="regex" if module == "regex" else None)

    def _extract_keyword_flags(self, call: ast.Call, env: Dict[str, ast.AST], flags: str) -> Tuple[str, List[str]]:
        notes: List[str] = []
        for keyword in call.keywords:
            if keyword.arg == "flags":
                extra, extra_notes = self._resolve_flags(keyword.value, env)
                flags = "".join(sorted(set(flags + extra)))
                notes.extend(extra_notes)
        return flags, notes

    def _emit_wrapper(self, call: ast.Call, wrapper_name: str, env: Dict[str, ast.AST]) -> None:
        params = self.wrapper_params.get(wrapper_name, {})
        for index, sink_name in params.items():
            if index >= len(call.args):
                continue
            pattern_node = call.args[index]
            data_node = call.args[index + 1] if index + 1 < len(call.args) else None
            self._emit(pattern_node, f"{wrapper_name}() -> re.{sink_name}", "re", data_node,
                       env, "", [], notes=[f"pattern forwarded through wrapper {wrapper_name}()"])

    # -- emission -----------------------------------------------------------
    def _emit(self, pattern_node: Optional[ast.AST], function: str, module: str,
              data_node: Optional[ast.AST], env: Dict[str, ast.AST], flags: str,
              flag_notes: List[str], notes: Optional[List[str]] = None,
              engine_hint: Optional[str] = None) -> None:
        resolved = self._resolve(pattern_node, env)
        line = getattr(pattern_node, "lineno", None) or getattr(pattern_node, "end_lineno", None) or 1
        column = getattr(pattern_node, "col_offset", None)
        if column is not None:
            column += 1
        data_expr = _unparse(data_node)
        input_control, input_evidence = classify_input_control(data_expr, "python")

        candidate_notes = list(flag_notes)
        if notes:
            candidate_notes.extend(notes)
        candidate_notes.extend(resolved.notes)
        if not resolved.resolved:
            candidate_notes.append("pattern value could not be resolved statically")
        candidate_notes = list(dict.fromkeys(candidate_notes))

        pattern = resolved.value
        raw = None
        if pattern is not None and module == "regex":
            engine_hint = engine_hint or "regex"

        self.candidates.append(make_candidate(
            package=self.package,
            version=self.version,
            language="python",
            rel_path=self.rel_path,
            line=line,
            column=column,
            function=function,
            pattern=pattern,
            flags=flags,
            source_type=resolved.source_type,
            input_control=input_control,
            input_evidence=input_evidence,
            raw_pattern=raw,
            extractor=EXTRACTOR_NAME,
            confidence=resolved.confidence if resolved.resolved else 0.4,
            notes=candidate_notes,
            engine_hint=engine_hint,
        ))


def _span(node: ast.AST) -> Tuple[int, int]:
    return (getattr(node, "lineno", 0) or 0, getattr(node, "col_offset", 0) or 0)


def _contains(parent: ast.AST, child: ast.AST) -> bool:
    for node in ast.walk(parent):
        if node is child:
            return True
    return False


def extract(package: str, version: str, rel_path: str, source: str) -> List[RegexCandidate]:
    return PythonExtractor(package, version, rel_path, source).extract()
