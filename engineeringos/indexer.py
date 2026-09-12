"""Local, source-preserving code map index backed by SQLite."""
from __future__ import annotations

import ast
import hashlib
import importlib
import re
import sqlite3
import os
from functools import lru_cache
from pathlib import Path

from .evidence import EvidenceItem, ToolHardFailure
from .security import allowed_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, digest TEXT NOT NULL, language TEXT NOT NULL, indexed_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS symbols(id INTEGER PRIMARY KEY, path TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL, line INTEGER NOT NULL, end_line INTEGER NOT NULL, UNIQUE(path,name,line));
CREATE TABLE IF NOT EXISTS edges(source_id INTEGER NOT NULL, target_name TEXT NOT NULL, kind TEXT NOT NULL, UNIQUE(source_id,target_name,kind));
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
"""

LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".rb": "ruby", ".php": "php",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".cs": "csharp", ".swift": "swift", ".scala": "scala", ".sc": "scala", ".lua": "lua", ".sh": "shell", ".bash": "shell",
    ".dart": "dart", ".ex": "elixir", ".exs": "elixir",
}
GENERIC_PATTERNS = {
    "javascript": [("class", re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")), ("function", re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)|\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\("))],
    "typescript": [("class", re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)")), ("function", re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)|\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\("))],
    "go": [("type", re.compile(r"\btype\s+([A-Za-z_]\w*)\s+(?:struct|interface)")), ("function", re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("))],
    "rust": [("struct", re.compile(r"\bstruct\s+([A-Za-z_]\w*)")), ("function", re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*\("))],
    "java": [("class", re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_]\w*)")), ("function", re.compile(r"\b(?:public|private|protected|static|final|synchronized|native|abstract|\s)+\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"))],
    "kotlin": [("class", re.compile(r"\b(?:class|interface|object)\s+([A-Za-z_]\w*)")), ("function", re.compile(r"\bfun\s+([A-Za-z_]\w*)\s*\("))],
    "ruby": [("class", re.compile(r"\bclass\s+([A-Za-z_]\w*)")), ("function", re.compile(r"\bdef\s+([A-Za-z_]\w*)"))],
    "php": [("class", re.compile(r"\bclass\s+([A-Za-z_]\w*)")), ("function", re.compile(r"\bfunction\s+([A-Za-z_]\w*)"))],
    "c": [("type", re.compile(r"\b(?:struct|enum|union)\s+([A-Za-z_]\w*)")), ("function", re.compile(r"(?m)^\s*(?!if\b|for\b|while\b|switch\b)(?:[A-Za-z_]\w*[\s*]+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"))],
    "cpp": [("type", re.compile(r"\b(?:class|struct|enum|union)\s+(?:class\s+)?([A-Za-z_]\w*)")), ("namespace", re.compile(r"\bnamespace\s+([A-Za-z_]\w*)")), ("function", re.compile(r"(?m)^\s*(?!if\b|for\b|while\b|switch\b)(?:[A-Za-z_:~<>]\w*[\s*&:<>]+)+([A-Za-z_~]\w*)\s*\([^;{}]*\)(?:\s+(?:const|noexcept|override|final))*\s*\{"))],
    "csharp": [("type", re.compile(r"\b(?:class|interface|record|struct|enum)\s+([A-Za-z_]\w*)")), ("method", re.compile(r"(?m)(?:^|[;{}])\s*(?:(?:public|private|protected|internal|static|virtual|override|async|sealed|partial|new)\s+)*(?:[A-Za-z_]\w*(?:<[^>]+>)?[?\[\]]*\s+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:=>|\{)"))],
    "swift": [("type", re.compile(r"\b(?:class|struct|protocol|enum|actor)\s+([A-Za-z_]\w*)")), ("function", re.compile(r"\bfunc\s+([A-Za-z_]\w*)\s*[<(]"))],
    "scala": [("type", re.compile(r"\b(?:class|trait|object|enum)\s+([A-Za-z_]\w*)")), ("function", re.compile(r"\bdef\s+([A-Za-z_]\w*)\s*(?:\[|\()"))],
    "lua": [("function", re.compile(r"(?m)^\s*(?:local\s+)?function\s+([A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)*)\s*\(")), ("function", re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*function\s*\("))],
    "shell": [("function", re.compile(r"(?m)^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{"))],
    "dart": [("type", re.compile(r"\b(?:class|mixin|enum|extension)\s+([A-Za-z_]\w*)")), ("function", re.compile(r"(?m)^\s*(?:[A-Za-z_]\w*(?:<[^>]+>)?[?]?\s+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:async\s*)?(?:=>|\{)"))],
    "elixir": [("module", re.compile(r"\bdefmodule\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)")), ("function", re.compile(r"\bdefp?\s+([a-z_]\w*)\s*(?:\(|do:)"))],
}

CALL_PATTERN = re.compile(r"\b(?:[A-Za-z_]\w*(?:::|\.|->))*([A-Za-z_~]\w*)\s*\(")
CALLABLE_KINDS = {"function", "method", "singleton_method"}
CALL_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "sizeof", "typeof", "alignof", "nameof",
    "function", "func", "fn", "def", "class", "struct", "interface", "enum", "record", "protocol",
    "assert", "match", "when", "unless", "with", "do", "print", "echo",
}

TREE_SITTER_GRAMMARS = {
    "javascript": ("tree_sitter_javascript", {"class_declaration": "class", "function_declaration": "function", "method_definition": "method"}),
    "typescript": ("tree_sitter_typescript", {"class_declaration": "class", "function_declaration": "function", "method_definition": "method"}),
    "go": ("tree_sitter_go", {"type_declaration": "type", "function_declaration": "function", "method_declaration": "method"}),
    "rust": ("tree_sitter_rust", {"struct_item": "struct", "function_item": "function", "impl_item": "impl"}),
    "java": ("tree_sitter_java", {"class_declaration": "class", "interface_declaration": "interface", "method_declaration": "method"}),
    "c": ("tree_sitter_c", {"struct_specifier": "type", "enum_specifier": "type", "union_specifier": "type", "function_definition": "function"}),
    "cpp": ("tree_sitter_cpp", {"class_specifier": "class", "struct_specifier": "struct", "enum_specifier": "enum", "namespace_definition": "namespace", "function_definition": "function"}),
    "csharp": ("tree_sitter_c_sharp", {"class_declaration": "class", "interface_declaration": "interface", "record_declaration": "record", "struct_declaration": "struct", "enum_declaration": "enum", "method_declaration": "method"}),
    "swift": ("tree_sitter_swift", {"class_declaration": "class", "protocol_declaration": "protocol", "struct_declaration": "struct", "enum_declaration": "enum", "function_declaration": "function"}),
    "scala": ("tree_sitter_scala", {"class_definition": "class", "trait_definition": "trait", "object_definition": "object", "enum_definition": "enum", "function_definition": "function"}),
    "ruby": ("tree_sitter_ruby", {"class": "class", "module": "module", "method": "method", "singleton_method": "method"}),
    "php": ("tree_sitter_php", {"class_declaration": "class", "interface_declaration": "interface", "trait_declaration": "trait", "function_definition": "function", "method_declaration": "method"}),
}

MAX_SOURCE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_INDEX_FILES = 100_000


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _db_path(repo: Path) -> Path:
    index_root = os.environ.get("ENGINEERINGOS_INDEX_ROOT")
    if index_root:
        identity = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()
        return Path(index_root).expanduser().resolve() / identity / "index.sqlite3"
    return repo / ".engineeringos" / "index.sqlite3"

def _db(repo: Path) -> sqlite3.Connection:
    db = _db_path(repo)
    db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(db, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    try:
        db.chmod(0o600)
    except OSError:
        pass
    return conn

@lru_cache(maxsize=None)
def _tree_sitter_language(language: str):
    grammar = TREE_SITTER_GRAMMARS.get(language)
    if not grammar:
        return None
    module_name, _ = grammar
    try:
        module = importlib.import_module(module_name)
        from tree_sitter import Language
        factory = getattr(module, "language", None)
        if factory is None and language == "typescript":
            factory = getattr(module, "language_typescript", None)
        if factory is None:
            return None
        value = factory()
        return value if isinstance(value, Language) else Language(value)
    except (ImportError, AttributeError, TypeError, ValueError, OSError):
        return None


def _tree_sitter_symbols(raw: bytes, language: str) -> list[tuple[str, str, int, int]] | None:
    grammar = TREE_SITTER_GRAMMARS.get(language)
    language_obj = _tree_sitter_language(language)
    if not grammar or language_obj is None:
        return None
    _, node_kinds = grammar
    try:
        from tree_sitter import Parser
        try:
            parser = Parser(language_obj)
        except TypeError:
            parser = Parser()
            parser.language = language_obj
        tree = parser.parse(raw)
    except (ImportError, AttributeError, TypeError, ValueError):
        return None
    found = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        kind = node_kinds.get(node.type)
        if kind:
            if language == "swift" and node.type == "class_declaration":
                declaration = raw[node.start_byte:node.end_byte].lstrip().split(None, 1)[0].decode("utf-8", errors="replace")
                if declaration in {"class", "struct", "actor", "enum"}:
                    kind = declaration
            name_node = node.child_by_field_name("name")
            if name_node is None:
                candidate = node.child_by_field_name("declarator")
                search = [candidate] if candidate is not None else list(node.children)
                name_node = None
                while search and name_node is None:
                    child = search.pop(0)
                    if child.type in {"identifier", "type_identifier", "field_identifier", "simple_identifier", "operator_name", "destructor_name", "constant"}:
                        name_node = child
                    else:
                        search[0:0] = list(child.children)
            if name_node:
                name = raw[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
                found.append((name, kind, node.start_point[0] + 1, node.end_point[0] + 1))
        stack.extend(reversed(node.children))
    return found


def parser_backend(language: str) -> str:
    if language == "python":
        return "python-ast"
    if _tree_sitter_language(language) is not None:
        return "tree-sitter"
    return "regex-fallback"


def _symbols(raw: bytes, rel: str, language: str) -> list[tuple[str, str, int, int]]:
    text = raw.decode("utf-8")
    if language == "python":
        try: tree = ast.parse(text, filename=rel)
        except (SyntaxError, UnicodeDecodeError): return []
        return [(node.name, "class" if isinstance(node, ast.ClassDef) else "function", node.lineno, getattr(node, "end_lineno", node.lineno)) for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    parsed = _tree_sitter_symbols(raw, language)
    found = list(parsed or [])
    identities = {(name, line) for name, _, line, _ in found}
    for kind, pattern in GENERIC_PATTERNS.get(language, []):
        for match in pattern.finditer(text):
            name = next((group for group in match.groups() if group), None)
            line = text.count("\n", 0, match.start()) + 1
            if name and (name, line) not in identities:
                found.append((name, kind, line, text.count("\n", 0, match.end()) + 1))
                identities.add((name, line))
    return list(dict.fromkeys(found))


def _edges(raw: bytes, rel: str, language: str, symbols: list[tuple[str, str, int, int]] | None = None) -> list[tuple[str, int, str, str]]:
    if language != "python":
        text = raw.decode("utf-8", errors="replace")
        callable_symbols = [(name, line) for name, kind, line, _ in (symbols or []) if kind in CALLABLE_KINDS]
        if not callable_symbols:
            return []
        edges: list[tuple[str, int, str, str]] = []
        for match in CALL_PATTERN.finditer(text):
            target = match.group(1)
            line = text.count("\n", 0, match.start()) + 1
            candidates = [(source_line, source_name) for source_name, source_line in callable_symbols if source_line <= line]
            if not candidates:
                continue
            source_line, source_name = max(candidates, key=lambda item: item[0])
            if target not in CALL_KEYWORDS and target != source_name:
                edges.append((source_name, source_line, target, "calls"))
        return list(dict.fromkeys(edges))
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=rel)
    except (SyntaxError, UnicodeDecodeError):
        return []
    edges: list[tuple[str, int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                target = child.func.id if isinstance(child.func, ast.Name) else child.func.attr if isinstance(child.func, ast.Attribute) else None
                if target:
                    edges.append((node.name, node.lineno, target, "calls"))
            elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load) and child.id != node.name:
                edges.append((node.name, node.lineno, child.id, "references"))
    return list(dict.fromkeys(edges))

def index_repo(repo_path: str) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    conn = _db(repo); changed = 0; oversized = 0; unreadable = 0
    max_files = max(1, int(os.environ.get("ENGINEERINGOS_MAX_INDEX_FILES", str(DEFAULT_MAX_INDEX_FILES))))
    current_paths: set[str] = set()
    try:
        for path in repo.rglob("*"):
            if any(part in {".git", ".engineeringos", "__pycache__"} for part in path.parts): continue
            language = LANGUAGES.get(path.suffix.lower())
            if not path.is_file() or not language: continue
            rel = str(path.relative_to(repo)); current_paths.add(rel)
            if len(current_paths) > max_files:
                raise ToolHardFailure(f"Can't index repository — it exceeds the configured limit of {max_files} source files. Narrow the repository or raise ENGINEERINGOS_MAX_INDEX_FILES.")
            try:
                if path.stat().st_size > MAX_SOURCE_BYTES:
                    oversized += 1
                    conn.execute("DELETE FROM symbols WHERE path=?", (rel,))
                    conn.execute("DELETE FROM files WHERE path=?", (rel,))
                    continue
                raw = path.read_bytes()
            except OSError:
                unreadable += 1
                continue
            digest = hashlib.sha256(raw).hexdigest()
            old = conn.execute("SELECT digest FROM files WHERE path=?", (rel,)).fetchone()
            if old and old[0] == digest: continue
            conn.execute("DELETE FROM symbols WHERE path=?", (rel,))
            conn.execute("DELETE FROM edges WHERE source_id NOT IN (SELECT id FROM symbols)")
            parsed_symbols = _symbols(raw, rel, language)
            for name, kind, line, end_line in parsed_symbols:
                conn.execute("INSERT OR IGNORE INTO symbols(path,name,kind,line,end_line) VALUES(?,?,?,?,?)", (rel,name,kind,line,end_line))
            for source_name, source_line, target_name, edge_kind in _edges(raw, rel, language, parsed_symbols):
                source = conn.execute("SELECT id FROM symbols WHERE path=? AND name=? AND line=?", (rel, source_name, source_line)).fetchone()
                if source:
                    conn.execute("INSERT OR IGNORE INTO edges(source_id,target_name,kind) VALUES(?,?,?)", (source[0], target_name, edge_kind))
            conn.execute("INSERT OR REPLACE INTO files(path,digest,language) VALUES(?,?,?)", (rel,digest,language)); changed += 1
        removed = [row[0] for row in conn.execute("SELECT path FROM files").fetchall() if row[0] not in current_paths]
        for rel in removed:
            conn.execute("DELETE FROM symbols WHERE path=?", (rel,))
            conn.execute("DELETE FROM files WHERE path=?", (rel,))
        conn.execute("DELETE FROM edges WHERE source_id NOT IN (SELECT id FROM symbols)")
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        edge_count = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        indexed_languages = [row[0] for row in conn.execute("SELECT DISTINCT language FROM files ORDER BY language")]
        backends = ", ".join(f"{language}={parser_backend(language)}" for language in indexed_languages)
        return [EvidenceItem("code_search", "local_index", f"Indexed {changed} changed source file(s), removed {len(removed)} deleted file(s), skipped {oversized} oversized and {unreadable} unreadable file(s); {count} symbols and {edge_count} reference edges available; parser backends: {backends}", str(_db_path(repo)))]
    finally: conn.close()

def find_symbol(repo_path: str, name: str, max_results: int = 20) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True); conn = _db(repo)
    try:
        limit = max(1, min(int(max_results), 500))
        rows = conn.execute("SELECT path,name,kind,line FROM symbols WHERE name LIKE ? ORDER BY path,line LIMIT ?", (f"%{name}%", limit)).fetchall()
        return [EvidenceItem("code_search", p, f"{kind} {n}", f"{p}#L{line}") for p,n,kind,line in rows]
    finally: conn.close()


def dependency_graph(repo_path: str, symbol: str, direction: str = "out", max_results: int = 50) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    if direction not in {"out", "in"}:
        raise ToolHardFailure("Can't inspect dependency graph — direction must be 'out' or 'in'.")
    conn = _db(repo)
    try:
        limit = max(1, min(int(max_results), 500))
        if direction == "out":
            rows = conn.execute("SELECT s.path, s.name, s.line, e.target_name, e.kind FROM symbols s JOIN edges e ON e.source_id=s.id WHERE s.name LIKE ? ORDER BY s.path, s.line LIMIT ?", (f"%{symbol}%", limit)).fetchall()
        else:
            rows = conn.execute("SELECT s.path, s.name, s.line, e.target_name, e.kind FROM symbols s JOIN edges e ON e.source_id=s.id WHERE e.target_name LIKE ? ORDER BY s.path, s.line LIMIT ?", (f"%{symbol}%", limit)).fetchall()
        return [EvidenceItem("code_search", path, f"{name} {kind} {target}", f"{path}#L{line}") for path, name, line, target, kind in rows]
    finally:
        conn.close()

def freshness(repo_path: str) -> EvidenceItem:
    repo = allowed_path(repo_path, must_be_dir=True); conn = _db(repo)
    try:
        stale = 0; indexed = 0
        for rel, digest in conn.execute("SELECT path,digest FROM files"):
            path = repo / rel
            indexed += 1
            try:
                changed = not path.exists() or _file_digest(path) != digest
            except OSError:
                changed = True
            if changed: stale += 1
        status = "fresh" if stale == 0 else "stale"
        return EvidenceItem("code_search", "local_index", f"Index status: {status}; {stale} of {indexed} indexed file(s) changed or disappeared", str(_db_path(repo)))
    finally: conn.close()
