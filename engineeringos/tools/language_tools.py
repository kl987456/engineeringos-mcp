"""Bounded language and build-ecosystem profiling for polyglot repositories."""
from __future__ import annotations

from collections import Counter

from .. import indexer
from ..evidence import EvidenceItem, ToolHardFailure
from ..filewalk import repository_files
from ..security import allowed_path

MANIFESTS = {
    "pyproject.toml": "Python", "requirements.txt": "Python", "package.json": "JavaScript/TypeScript",
    "go.mod": "Go", "Cargo.toml": "Rust", "pom.xml": "Java", "build.gradle": "Java/Kotlin",
    "build.gradle.kts": "Kotlin", "CMakeLists.txt": "C/C++", "Makefile": "C/C++/native",
    "Package.swift": "Swift", "build.sbt": "Scala", "pubspec.yaml": "Dart", "mix.exs": "Elixir",
    "Gemfile": "Ruby", "composer.json": "PHP",
}


def _is_test(path, language: str) -> bool:
    name = path.name.lower()
    parts = {part.lower() for part in path.parts}
    if "test" in parts or "tests" in parts or "spec" in parts:
        return True
    patterns = {
        "python": name.startswith("test_") or name.endswith("_test.py"),
        "javascript": ".test." in name or ".spec." in name,
        "typescript": ".test." in name or ".spec." in name,
        "go": name.endswith("_test.go"),
        "rust": name.endswith("_test.rs"),
        "java": name.endswith("test.java") or name.startswith("test"),
        "kotlin": name.endswith("test.kt"),
        "csharp": name.endswith("tests.cs") or name.endswith("test.cs"),
        "swift": name.endswith("tests.swift") or name.endswith("test.swift"),
        "scala": name.endswith("spec.scala") or name.endswith("test.scala"),
        "ruby": name.endswith("_spec.rb") or name.startswith("test_"),
        "php": name.endswith("test.php"),
        "dart": name.endswith("_test.dart"),
        "elixir": name.endswith("_test.exs"),
    }
    return patterns.get(language, False)


def language_profile(repo_path: str) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    files = Counter()
    tests = Counter()
    sizes = Counter()
    manifests: list[tuple[str, str]] = []
    unreadable = 0
    for path in repository_files(repo):
        language = indexer.LANGUAGES.get(path.suffix.lower())
        if language:
            files[language] += 1
            tests[language] += int(_is_test(path.relative_to(repo), language))
            try:
                sizes[language] += path.stat().st_size
            except OSError:
                unreadable += 1
        ecosystem = MANIFESTS.get(path.name)
        if ecosystem:
            manifests.append((str(path.relative_to(repo)).replace("\\", "/"), ecosystem))
    if not files:
        raise ToolHardFailure("Can't profile languages — no supported source files were found in this repository.")
    evidence = [
        EvidenceItem(
            "code_search",
            "language_profile",
            f"{language}: {count} source file(s), {tests[language]} detected test file(s), {sizes[language]} bytes; index backend {indexer.parser_backend(language)}",
            str(repo),
        )
        for language, count in sorted(files.items(), key=lambda item: (-item[1], item[0]))
    ]
    manifest_summary = ", ".join(f"{path} ({ecosystem})" for path, ecosystem in sorted(manifests)) or "none detected"
    evidence.append(EvidenceItem("code_search", "language_profile", f"Build/dependency manifests: {manifest_summary}; unreadable source files: {unreadable}", str(repo)))
    return evidence
