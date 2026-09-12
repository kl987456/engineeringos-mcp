"""Portable source-free code-map export, validation, storage, and queries."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path, PurePosixPath
from typing import Any

from .audit import current_tenant
from .evidence import EvidenceItem, ToolHardFailure
from .indexer import LANGUAGES, SCHEMA, _db, _db_path, freshness
from .security import allowed_path

FORMAT = "engineeringos.code-map/v1"
MAX_FILES = 100_000
MAX_SYMBOLS = 250_000
MAX_EDGES = 500_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_FILE_KEYS = {"path", "digest", "language"}
_SYMBOL_KEYS = {"path", "name", "kind", "line", "end_line"}
_EDGE_KEYS = {"source_path", "source_name", "source_line", "target_name", "kind"}
_TOP_KEYS = {"format", "source_fingerprint", "files", "symbols", "edges"}


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ToolHardFailure(f"Can't use code map — {field} must be non-empty text no longer than {maximum} characters.")
    return value


def _relative_path(value: Any) -> str:
    text = _text(value, "path", 1_024).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ToolHardFailure("Can't use code map — every file path must be a normalized relative path without traversal.")
    return str(path)


def _positive_line(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 100_000_000:
        raise ToolHardFailure(f"Can't use code map — {field} must be a positive line number.")
    return value


def _fingerprint(files: list[dict]) -> str:
    canonical = json.dumps(sorted(files, key=lambda item: item["path"]), separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def export_code_map(repo_path: str) -> dict:
    """Export indexed structural metadata only; raw source is never read here."""
    repo = allowed_path(repo_path, must_be_dir=True)
    db_path = _db_path(repo)
    if not db_path.is_file():
        raise ToolHardFailure("Can't export code map — index_code must complete successfully first.")
    state = freshness(str(repo))
    if "Index status: stale" in state.summary:
        raise ToolHardFailure("Can't export code map — the local index is stale. Run index_code again before exporting.")
    conn = _db(repo)
    try:
        files = [
            {"path": path.replace("\\", "/"), "digest": digest, "language": language}
            for path, digest, language in conn.execute("SELECT path,digest,language FROM files ORDER BY path")
        ]
        symbols = [
            {"path": path.replace("\\", "/"), "name": name, "kind": kind, "line": line, "end_line": end_line}
            for path, name, kind, line, end_line in conn.execute("SELECT path,name,kind,line,end_line FROM symbols ORDER BY path,line,name")
        ]
        edges = [
            {"source_path": path.replace("\\", "/"), "source_name": name, "source_line": line, "target_name": target, "kind": kind}
            for path, name, line, target, kind in conn.execute(
                "SELECT s.path,s.name,s.line,e.target_name,e.kind FROM symbols s JOIN edges e ON e.source_id=s.id ORDER BY s.path,s.line,e.target_name"
            )
        ]
    finally:
        conn.close()
    if len(files) > MAX_FILES or len(symbols) > MAX_SYMBOLS or len(edges) > MAX_EDGES:
        raise ToolHardFailure("Can't export code map — indexed metadata exceeds the portable-map safety limits.")
    return {"format": FORMAT, "source_fingerprint": _fingerprint(files), "files": files, "symbols": symbols, "edges": edges}


def validate_code_map(payload: Any) -> dict:
    if not isinstance(payload, dict) or set(payload) != _TOP_KEYS or payload.get("format") != FORMAT:
        raise ToolHardFailure("Can't use code map — the payload does not match the strict EngineeringOS code-map v1 schema.")
    raw_files, raw_symbols, raw_edges = payload.get("files"), payload.get("symbols"), payload.get("edges")
    if not isinstance(raw_files, list) or not isinstance(raw_symbols, list) or not isinstance(raw_edges, list):
        raise ToolHardFailure("Can't use code map — files, symbols, and edges must be arrays.")
    if len(raw_files) > MAX_FILES or len(raw_symbols) > MAX_SYMBOLS or len(raw_edges) > MAX_EDGES:
        raise ToolHardFailure("Can't use code map — metadata exceeds the configured format limits.")

    files: list[dict] = []
    known_paths: set[str] = set()
    known_languages = set(LANGUAGES.values())
    for item in raw_files:
        if not isinstance(item, dict) or set(item) != _FILE_KEYS:
            raise ToolHardFailure("Can't use code map — a file record contains unknown or missing fields.")
        path = _relative_path(item["path"])
        digest = _text(item["digest"], "digest", 64)
        language = _text(item["language"], "language", 32)
        if not _DIGEST.fullmatch(digest) or language not in known_languages or path in known_paths:
            raise ToolHardFailure("Can't use code map — a file record has an invalid digest, language, or duplicate path.")
        known_paths.add(path)
        files.append({"path": path, "digest": digest, "language": language})

    symbols: list[dict] = []
    known_symbols: set[tuple[str, str, int]] = set()
    for item in raw_symbols:
        if not isinstance(item, dict) or set(item) != _SYMBOL_KEYS:
            raise ToolHardFailure("Can't use code map — a symbol record contains unknown or missing fields.")
        path = _relative_path(item["path"])
        name = _text(item["name"], "symbol name", 512)
        kind = _text(item["kind"], "symbol kind", 64)
        line = _positive_line(item["line"], "line")
        end_line = _positive_line(item["end_line"], "end_line")
        identity = (path, name, line)
        if path not in known_paths or end_line < line or identity in known_symbols:
            raise ToolHardFailure("Can't use code map — a symbol has an unknown path, invalid range, or duplicate identity.")
        known_symbols.add(identity)
        symbols.append({"path": path, "name": name, "kind": kind, "line": line, "end_line": end_line})

    edges: list[dict] = []
    seen_edges: set[tuple[str, str, int, str, str]] = set()
    for item in raw_edges:
        if not isinstance(item, dict) or set(item) != _EDGE_KEYS:
            raise ToolHardFailure("Can't use code map — an edge record contains unknown or missing fields.")
        source_path = _relative_path(item["source_path"])
        source_name = _text(item["source_name"], "edge source", 512)
        source_line = _positive_line(item["source_line"], "source_line")
        target_name = _text(item["target_name"], "edge target", 512)
        kind = _text(item["kind"], "edge kind", 64)
        identity = (source_path, source_name, source_line, target_name, kind)
        if (source_path, source_name, source_line) not in known_symbols or identity in seen_edges:
            raise ToolHardFailure("Can't use code map — an edge source is unknown or the edge is duplicated.")
        seen_edges.add(identity)
        edges.append({"source_path": source_path, "source_name": source_name, "source_line": source_line, "target_name": target_name, "kind": kind})

    fingerprint = _text(payload.get("source_fingerprint"), "source_fingerprint", 64)
    if not _DIGEST.fullmatch(fingerprint) or fingerprint != _fingerprint(files):
        raise ToolHardFailure("Can't use code map — source_fingerprint does not match the file metadata.")
    return {"format": FORMAT, "source_fingerprint": fingerprint, "files": files, "symbols": symbols, "edges": edges}


def _map_db_path(project_id: str) -> Path:
    tenant = current_tenant()
    if tenant == "unknown":
        tenant = "local"
    if not _IDENTIFIER.fullmatch(project_id) or not _IDENTIFIER.fullmatch(tenant):
        raise ToolHardFailure("Can't access code map — tenant and project identifiers must use safe identifier characters.")
    root_value = os.environ.get("ENGINEERINGOS_MAP_ROOT") or os.environ.get("ENGINEERINGOS_INDEX_ROOT")
    if not root_value:
        raise ToolHardFailure("Can't access code map — configure ENGINEERINGOS_MAP_ROOT or ENGINEERINGOS_INDEX_ROOT.")
    identity = hashlib.sha256(f"{tenant}\x00{project_id}".encode("utf-8")).hexdigest()
    return Path(root_value).expanduser().resolve() / "maps" / identity / "map.sqlite3"


def _map_db(project_id: str) -> sqlite3.Connection:
    path = _map_db_path(project_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(path, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return conn


def ingest_code_map(project_id: str, payload: Any) -> list[EvidenceItem]:
    clean = validate_code_map(payload)
    conn = _map_db(project_id)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM edges")
        conn.execute("DELETE FROM symbols")
        conn.execute("DELETE FROM files")
        conn.executemany("INSERT INTO files(path,digest,language) VALUES(:path,:digest,:language)", clean["files"])
        conn.executemany("INSERT INTO symbols(path,name,kind,line,end_line) VALUES(:path,:name,:kind,:line,:end_line)", clean["symbols"])
        for edge in clean["edges"]:
            source = conn.execute(
                "SELECT id FROM symbols WHERE path=? AND name=? AND line=?",
                (edge["source_path"], edge["source_name"], edge["source_line"]),
            ).fetchone()
            conn.execute("INSERT INTO edges(source_id,target_name,kind) VALUES(?,?,?)", (source[0], edge["target_name"], edge["kind"]))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return [EvidenceItem("code_search", "hosted_code_map", f"Imported source-free map with {len(clean['files'])} files, {len(clean['symbols'])} symbols, and {len(clean['edges'])} edges; fingerprint {clean['source_fingerprint'][:12]}", f"code-map://{project_id}")]


def map_find_symbol(project_id: str, name: str, max_results: int = 20) -> list[EvidenceItem]:
    if not isinstance(name, str):
        raise ToolHardFailure("Can't query code map — symbol name must be text.")
    conn = _map_db(project_id)
    try:
        if conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0:
            raise ToolHardFailure("Can't query code map — no map has been imported for this project.")
        limit = max(1, min(int(max_results), 500))
        rows = conn.execute("SELECT path,name,kind,line FROM symbols WHERE name LIKE ? ORDER BY path,line LIMIT ?", (f"%{name}%", limit)).fetchall()
        return [EvidenceItem("code_search", "hosted_code_map", f"{kind} {symbol}", f"{path}#L{line}") for path, symbol, kind, line in rows]
    finally:
        conn.close()


def map_dependency_graph(project_id: str, symbol: str, direction: str = "out", max_results: int = 50) -> list[EvidenceItem]:
    if direction not in {"out", "in"}:
        raise ToolHardFailure("Can't query code map — direction must be 'out' or 'in'.")
    conn = _map_db(project_id)
    try:
        if conn.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0:
            raise ToolHardFailure("Can't query code map — no map has been imported for this project.")
        limit = max(1, min(int(max_results), 500))
        if direction == "out":
            rows = conn.execute("SELECT s.path,s.name,s.line,e.target_name,e.kind FROM symbols s JOIN edges e ON e.source_id=s.id WHERE s.name LIKE ? ORDER BY s.path,s.line LIMIT ?", (f"%{symbol}%", limit)).fetchall()
        else:
            rows = conn.execute("SELECT s.path,s.name,s.line,e.target_name,e.kind FROM symbols s JOIN edges e ON e.source_id=s.id WHERE e.target_name LIKE ? ORDER BY s.path,s.line LIMIT ?", (f"%{symbol}%", limit)).fetchall()
        return [EvidenceItem("code_search", "hosted_code_map", f"{name} {kind} {target}", f"{path}#L{line}") for path, name, line, target, kind in rows]
    finally:
        conn.close()


def map_status(project_id: str, source_fingerprint: str | None = None) -> list[EvidenceItem]:
    """Report map counts and optionally compare a customer's current fingerprint."""
    if source_fingerprint is not None and (not isinstance(source_fingerprint, str) or not _DIGEST.fullmatch(source_fingerprint)):
        raise ToolHardFailure("Can't inspect code map — source_fingerprint must be a lowercase SHA-256 digest.")
    conn = _map_db(project_id)
    try:
        files = [{"path": path, "digest": digest, "language": language} for path, digest, language in conn.execute("SELECT path,digest,language FROM files")]
        if not files:
            raise ToolHardFailure("Can't inspect code map — no map has been imported for this project.")
        symbol_count = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        edge_count = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
    finally:
        conn.close()
    current = _fingerprint(files)
    comparison = "comparison not requested"
    if source_fingerprint is not None:
        comparison = "matches supplied fingerprint" if source_fingerprint == current else "does not match supplied fingerprint"
    return [EvidenceItem("code_search", "hosted_code_map", f"Map has {len(files)} files, {symbol_count} symbols, and {edge_count} edges; {comparison}; fingerprint {current[:12]}", f"code-map://{project_id}")]
