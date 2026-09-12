"""Bounded, source-aware code search with deterministic evidence."""
from __future__ import annotations

from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..filewalk import repository_files

SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb", ".php", ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".cs", ".swift", ".scala", ".sc", ".lua", ".sh", ".bash", ".dart", ".ex", ".exs", ".sql", ".yaml", ".yml", ".json", ".toml", ".xml", ".md"}
IGNORED_PARTS = {".git", ".engineeringos", "__pycache__", "node_modules", "target", ".venv", "venv"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def search_code(repo_path: str, query: str, max_results: int = 20) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    if not isinstance(query, str) or not query.strip():
        raise ToolHardFailure("Can't search code — the query is empty. Provide a specific text or symbol name.")
    max_results = max(1, min(int(max_results), 1_000))
    items: list[EvidenceItem] = []
    for path in repository_files(repo):
        if len(items) >= max_results:
            break
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        relative = str(path.relative_to(repo))
        for line_number, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
            if query in line:
                items.append(EvidenceItem("code_search", relative, line.strip()[:200], f"{relative}#L{line_number}"))
                if len(items) >= max_results:
                    break
    return items
