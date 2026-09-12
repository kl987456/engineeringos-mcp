"""Default (non-operator-configured) backend for `lsp_symbols`, used only
when ENGINEERINGOS_LSP_ADAPTER is unset. Backed by the optional `multilspy`
extra (`pip install -e ".[lsp]"`).

Deliberately narrow scope, both verified empirically rather than assumed:

- **Windows is disabled by default.** A live test against a trivial 6-line
  Python file hung for several minutes even with a 30-second timeout passed
  to `SyncLanguageServer.create()` — the timeout did not bound startup on
  this platform. The identical scenario on a GitHub Actions Ubuntu runner
  completed correctly in under 2 seconds. Until the Windows-specific cause
  is understood, this backend does not run there by default; set
  ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS=1 to try it anyway at your own
  risk (still bounded by the same timeout parameter, which is exactly what
  did not work in testing).
- **Only Python is enabled by default**, even though multilspy also lists
  Rust/Java/Kotlin/Go/JS/TS/Ruby/C#/Dart. Python needs no external
  download (multilspy depends on `jedi-language-server` directly, a normal
  pip package) and was the one language actually verified end-to-end. The
  other languages' language servers are not bundled and may need to be
  independently installed or downloaded — each needs its own verification
  pass before being trusted as a silent default, per ROADMAP.md.
"""
from __future__ import annotations

import platform
import os
from pathlib import Path

from ..evidence import EvidenceItem, ToolHardFailure

MAX_SYMBOLS = 500

DEFAULT_LANGUAGES = {"python"}

_SYMBOL_KINDS = {
    1: "file", 2: "module", 3: "namespace", 4: "package", 5: "class", 6: "method",
    7: "property", 8: "field", 9: "constructor", 10: "enum", 11: "interface",
    12: "function", 13: "variable", 14: "constant", 22: "enum_member", 23: "struct",
}


def _windows_allowed() -> bool:
    return os.environ.get("ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS", "0").strip().lower() in {"1", "true", "yes"}


def is_available(language: str | None) -> bool:
    """Cheap, side-effect-free check — does not start a server or import
    multilspy. Used by capabilities()/preflight so unavailable languages
    are never mistaken for supported ones."""
    if language not in DEFAULT_LANGUAGES:
        return False
    if platform.system() == "Windows" and not _windows_allowed():
        return False
    try:
        import multilspy  # noqa: F401
    except ImportError:
        return False
    return True


def symbols(repo: Path, file_path: str, language: str | None, timeout: int) -> list[EvidenceItem]:
    resolved_language = language or "python"
    if not is_available(resolved_language):
        if platform.system() == "Windows" and resolved_language in DEFAULT_LANGUAGES:
            raise ToolHardFailure(
                "Can't resolve structural symbols — the default backend is disabled on Windows "
                "(it hung in testing); configure ENGINEERINGOS_LSP_ADAPTER, or set "
                "ENGINEERINGOS_LSP_DEFAULT_FORCE_WINDOWS=1 to try it anyway."
            )
        raise ToolHardFailure(
            f"Can't resolve structural symbols — no default backend supports '{resolved_language}'. "
            "Configure ENGINEERINGOS_LSP_ADAPTER for this language."
        )
    candidate = (repo / file_path).resolve()
    if candidate != repo and repo not in candidate.parents or not candidate.is_file():
        raise ToolHardFailure("Can't resolve structural symbols — the requested file is outside the repository or unavailable.")
    bounded_timeout = max(1, min(int(timeout), 120))

    from multilspy import SyncLanguageServer
    from multilspy.multilspy_config import MultilspyConfig, Language
    from multilspy.multilspy_logger import MultilspyLogger

    try:
        config = MultilspyConfig(code_language=Language(resolved_language))
        logger = MultilspyLogger()
        server = SyncLanguageServer.create(config, logger, str(repo), timeout=bounded_timeout)
        with server.start_server():
            raw_symbols, _tree = server.request_document_symbols(str(candidate.relative_to(repo)))
    except ToolHardFailure:
        raise
    except Exception as exc:
        # multilspy is young (pre-1.0) research-grade software wrapping real
        # language-server subprocesses; it can raise all sorts of internal
        # errors we cannot enumerate in advance. The safe behavior here is
        # always a clear ToolHardFailure, never an uncaught crash — the
        # calling agent is no worse off than if this backend didn't exist.
        raise ToolHardFailure(f"Can't resolve structural symbols — the default backend failed: {exc}.")

    return _convert_symbols(raw_symbols, file_path)


def _convert_symbols(raw_symbols: object, file_path: str) -> list[EvidenceItem]:
    """Pure conversion from multilspy's raw UnifiedSymbolInformation dicts
    (field shape confirmed empirically — see ROADMAP.md) to this project's
    EvidenceItem shape. Kept separate from `symbols()` so it's testable
    without multilspy installed."""
    if not isinstance(raw_symbols, list) or len(raw_symbols) > MAX_SYMBOLS:
        raise ToolHardFailure("Can't resolve structural symbols — the default backend returned an invalid or unbounded symbol list.")
    evidence = []
    for item in raw_symbols[:MAX_SYMBOLS]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"][:200]
        kind = _SYMBOL_KINDS.get(item.get("kind"), "symbol")
        symbol_range = item.get("range") if isinstance(item.get("range"), dict) else {}
        start = symbol_range.get("start", {}) if isinstance(symbol_range.get("start"), dict) else {}
        end = symbol_range.get("end", {}) if isinstance(symbol_range.get("end"), dict) else {}
        line = max(1, int(start.get("line", 0)) + 1)  # LSP lines are 0-indexed; this project's evidence is 1-indexed
        end_line = max(line, int(end.get("line", start.get("line", 0))) + 1)
        evidence.append(EvidenceItem("code_search", "lsp-default", f"{kind} {name}", f"{file_path}#L{line}-L{end_line}"))
    return evidence
