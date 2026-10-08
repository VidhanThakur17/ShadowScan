"""AST-based JavaScript analysis with bounded static data-flow.

This is a *layered* addition on top of the existing lightweight extractor in
:mod:`shadow_scan.recon.jsanalyze`; it does not replace it. The pipeline runs
the lightweight pass first, then this AST pass, then correlates.

It uses tree-sitter (optional). When tree-sitter is unavailable, :func:`analyze`
returns no AST findings and the caller falls back to the lightweight extractor,
so this is never a hard dependency.

Extracted structures:

* ``fetch("/api/users")`` / ``fetch(`${base}/users/${id}`)``
* ``axios.get/post/put/...("/path")`` with the HTTP method
* ``new WebSocket("wss://...")``
* route/config objects: ``{ path: "/users", method: "post" }``, ``baseURL: "..."``
* GraphQL operation names from ``gql`...``` / query strings

Data-flow "lite" resolves obvious values only — string constants, simple
aliases, ``a + b`` concatenation and template literals built from them — with a
strict depth/visited bound. Unresolvable dynamic parts become ``{dynamic}``.
No JavaScript is executed; there is no control-flow following.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..recon.models import FindingType, JsFinding

try:
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser

    _LANGUAGE = Language(_tsjs.language())
    AST_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when tree-sitter is absent
    _LANGUAGE = None
    AST_AVAILABLE = False

MAX_RESOLVE_DEPTH = 6
MAX_SOURCE_BYTES = 4 * 1024 * 1024
_HTTP_CALL_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
                      "delete": "DELETE", "head": "HEAD", "options": "OPTIONS", "request": "UNKNOWN"}
_PATHISH_RE = re.compile(r"^(?:https?://|wss?://|/)[^\s]*$", re.I)


@dataclass(frozen=True, slots=True)
class AstEndpoint:
    value: str                    # resolved URL/path, with {dynamic} for unresolved parts
    method: str = "UNKNOWN"
    confidence: float = 0.6
    dynamic_params: tuple[str, ...] = ()   # identifier names that filled dynamic slots
    kind: str = "endpoint"        # "endpoint" | "websocket" | "route" | "graphql"


@dataclass(slots=True)
class AstResult:
    endpoints: list[AstEndpoint] = field(default_factory=list)
    base_urls: list[str] = field(default_factory=list)
    route_params: list[str] = field(default_factory=list)
    graphql_ops: list[str] = field(default_factory=list)
    available: bool = True

    def to_findings(self) -> list[JsFinding]:
        """Convert to the recon JsFinding model so storage/correlation are shared."""
        out: list[JsFinding] = []
        for e in self.endpoints:
            ftype = FindingType.ENDPOINT_CANDIDATE
            if e.kind == "route":
                ftype = FindingType.ROUTE_CANDIDATE
            out.append(JsFinding(ftype, _annotate(e), e.confidence, evidence=f"ast:{e.method}"))
        for param in dict.fromkeys(self.route_params):
            out.append(JsFinding(FindingType.PARAMETER_CANDIDATE, param, 0.6, evidence="ast"))
        for op in dict.fromkeys(self.graphql_ops):
            out.append(JsFinding(FindingType.GRAPHQL_CANDIDATE, op, 0.6, evidence="ast:graphql"))
        return out


def _annotate(e: AstEndpoint) -> str:
    return e.value


def _parser() -> "Parser":
    try:
        return Parser(_LANGUAGE)
    except TypeError:  # older/newer binding signature
        p = Parser()
        p.language = _LANGUAGE
        return p


class _Analyzer:
    def __init__(self, source: bytes) -> None:
        self._src = source
        self._consts: dict[str, str | None] = {}
        self.result = AstResult()

    def text(self, node) -> str:
        return self._src[node.start_byte:node.end_byte].decode("utf-8", "replace")

    def run(self) -> AstResult:
        tree = _parser().parse(self._src)
        root = tree.root_node
        self._collect_constants(root)
        self._walk(root)
        # Deduplicate endpoints by (value, method).
        seen: set[tuple[str, str]] = set()
        unique: list[AstEndpoint] = []
        for e in self.result.endpoints:
            key = (e.value, e.method)
            if key not in seen:
                seen.add(key)
                unique.append(e)
        self.result.endpoints = unique
        return self.result

    # -- constant collection (data-flow lite) ------------------------------------------

    def _collect_constants(self, root) -> None:
        """Record ``const/let/var name = <string-ish>`` bindings, then resolve them.

        Gather value nodes in source order first, then run a few bounded fixpoint
        passes so forward references (``route = api + "/x"`` before ``api``'s own
        binding is seen) still resolve. Only the first binding of a name is kept.
        """
        bindings: list[tuple[str, object]] = []
        seen_names: set[str] = set()
        stack = [root]
        ordered: list = []
        while stack:
            node = stack.pop()
            ordered.append(node)
            for child in reversed(node.children):
                stack.append(child)
        for node in ordered:
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is not None and name_node.type == "identifier" and value_node is not None:
                    name = self.text(name_node)
                    if name not in seen_names:
                        seen_names.add(name)
                        bindings.append((name, value_node))
                        self._consts[name] = None
        # Fixpoint: at most len(bindings) passes (bounded), stop when nothing changes.
        for _ in range(min(len(bindings), MAX_RESOLVE_DEPTH + 2) + 1):
            changed = False
            for name, value_node in bindings:
                if self._consts.get(name) is None:
                    resolved = self._try_resolve(value_node, depth=0, visiting=frozenset({name}))
                    if resolved is not None:
                        self._consts[name] = resolved
                        changed = True
            if not changed:
                break

    def _try_resolve(self, node, depth: int, visiting: frozenset[str]) -> str | None:
        """Resolve a node to a static string if obvious; else None. Strictly bounded."""
        if depth > MAX_RESOLVE_DEPTH:
            return None
        t = node.type
        if t == "string":
            return self._string_value(node)
        if t == "template_string":
            return self._template_value(node, depth, visiting)
        if t == "identifier":
            name = self.text(node)
            if name in visiting:            # cycle guard
                return None
            value = self._consts.get(name, ...)
            if value is ...:
                return None
            return value
        if t == "binary_expression":        # a + b
            op = node.child_by_field_name("operator")
            if op is not None and self.text(op) != "+":
                return None
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                return None
            lv = self._try_resolve(left, depth + 1, visiting)
            rv = self._try_resolve(right, depth + 1, visiting)
            if lv is None or rv is None:
                return None
            return lv + rv
        if t == "parenthesized_expression" and node.named_child_count == 1:
            return self._try_resolve(node.named_children[0], depth + 1, visiting)
        return None

    def _string_value(self, node) -> str:
        raw = self.text(node)
        if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
            return raw[1:-1]
        return raw

    def _template_value(self, node, depth: int, visiting: frozenset[str]) -> str:
        """Resolve a template literal; dynamic ${...} become {dynamic} or {name}."""
        parts: list[str] = []
        for child in node.children:
            if child.type == "string_fragment":
                parts.append(self.text(child))
            elif child.type == "template_substitution":
                inner = [c for c in child.named_children]
                expr = inner[0] if inner else None
                resolved = self._try_resolve(expr, depth + 1, visiting) if expr is not None else None
                if resolved is not None:
                    parts.append(resolved)
                else:
                    name = self.text(expr) if expr is not None else "dynamic"
                    simple = name if re.match(r"^[A-Za-z_$][\w$.]*$", name) else "dynamic"
                    parts.append("{" + ("dynamic" if simple == "dynamic" else simple) + "}")
                    if simple != "dynamic":
                        self.result.route_params.append(simple.split(".")[-1])
            elif child.type in ("`",):
                continue
        return "".join(parts)

    # -- traversal for call sites / route objects --------------------------------------

    def _walk(self, root) -> None:
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                self._handle_call(node)
            elif node.type == "new_expression":
                self._handle_new(node)
            elif node.type in ("object", "object_pattern"):
                self._handle_object(node)
            for child in node.children:
                stack.append(child)

    def _arg_nodes(self, call):
        args = call.child_by_field_name("arguments")
        return [c for c in args.named_children] if args is not None else []

    def _handle_call(self, call) -> None:
        func = call.child_by_field_name("function")
        if func is None:
            return
        method = "UNKNOWN"
        name = ""
        if func.type == "identifier":
            name = self.text(func)
        elif func.type == "member_expression":
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            obj_name = self.text(obj) if obj is not None else ""
            prop_name = self.text(prop) if prop is not None else ""
            name = obj_name
            if obj_name in ("axios", "http", "client", "api", "$http") and prop_name in _HTTP_CALL_METHODS:
                method = _HTTP_CALL_METHODS[prop_name]
            elif prop_name in ("get", "post", "put", "patch", "delete") and obj_name.lower() in ("axios", "api", "http"):
                method = _HTTP_CALL_METHODS.get(prop_name, "UNKNOWN")
        args = self._arg_nodes(call)
        if not args:
            return
        if name == "fetch" or method != "UNKNOWN" or name in ("fetch", "request"):
            first = args[0]
            resolved = self._try_resolve(first, depth=0, visiting=frozenset())
            if resolved and _PATHISH_RE.match(resolved):
                dynamic = tuple(re.findall(r"\{([A-Za-z_][\w]*)\}", resolved))
                conf = 0.85 if "{dynamic}" not in resolved else 0.7
                self.result.endpoints.append(AstEndpoint(resolved, method, conf, dynamic))
            # Method from fetch's 2nd-arg options object: { method: "POST" }.
            if name == "fetch" and len(args) >= 2 and method == "UNKNOWN":
                opt_method = self._object_method(args[1])
                if opt_method and self.result.endpoints and self.result.endpoints[-1].value == resolved:
                    last = self.result.endpoints[-1]
                    self.result.endpoints[-1] = AstEndpoint(last.value, opt_method, last.confidence, last.dynamic_params)
        if name == "gql" or (func.type == "identifier" and name == "gql"):
            self._collect_graphql(args[0])

    def _handle_new(self, node) -> None:
        ctor = node.child_by_field_name("constructor")
        if ctor is None or self.text(ctor) != "WebSocket":
            return
        args = self._arg_nodes(node)
        if args:
            resolved = self._try_resolve(args[0], 0, frozenset())
            if resolved and _PATHISH_RE.match(resolved):
                self.result.endpoints.append(AstEndpoint(resolved, "UNKNOWN", 0.8, kind="websocket"))

    def _object_method(self, node) -> str | None:
        if node.type != "object":
            return None
        for pair in node.named_children:
            if pair.type != "pair":
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if key is not None and self.text(key).strip("\"'") == "method" and value is not None:
                v = self._try_resolve(value, 0, frozenset())
                if v:
                    return v.upper()
        return None

    def _handle_object(self, node) -> None:
        """Route/config objects: capture baseURL and {path, method} route definitions."""
        path_val: str | None = None
        method_val = "UNKNOWN"
        for pair in node.named_children:
            if pair.type != "pair":
                continue
            key_node = pair.child_by_field_name("key")
            value_node = pair.child_by_field_name("value")
            if key_node is None or value_node is None:
                continue
            key = self.text(key_node).strip("\"'")
            if key in ("baseURL", "baseUrl", "base_url", "apiUrl", "apiBase"):
                v = self._try_resolve(value_node, 0, frozenset())
                if v:
                    self.result.base_urls.append(v)
            elif key in ("path", "url", "route", "endpoint"):
                v = self._try_resolve(value_node, 0, frozenset())
                if v and _PATHISH_RE.match(v):
                    path_val = v
            elif key in ("method", "type") and value_node.type == "string":
                mv = self._string_value(value_node).upper()
                if mv in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    method_val = mv
        if path_val is not None:
            self.result.endpoints.append(AstEndpoint(path_val, method_val, 0.75, kind="route"))

    def _collect_graphql(self, node) -> None:
        text = self.text(node)
        for m in re.finditer(r"\b(?:query|mutation|subscription)\s+([A-Za-z_]\w*)", text):
            self.result.graphql_ops.append(m.group(1))


def analyze(source: str) -> AstResult:
    """Analyze JavaScript source with the AST engine. Safe on any input."""
    if not AST_AVAILABLE:
        return AstResult(available=False)
    data = source.encode("utf-8", "replace")
    if len(data) > MAX_SOURCE_BYTES:
        data = data[:MAX_SOURCE_BYTES]
    try:
        return _Analyzer(data).run()
    except Exception:  # pathological input must never crash analysis
        return AstResult(available=True)
