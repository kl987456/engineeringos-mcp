"""Deterministic dependency-manifest inventory; not a vulnerability oracle."""
from __future__ import annotations
from pathlib import Path
from ..evidence import EvidenceItem, ToolHardFailure
from ..security import allowed_path
from ..filewalk import repository_files

MANIFESTS = {
    "requirements.txt":"python", "pyproject.toml":"python", "package.json":"javascript", "package-lock.json":"javascript",
    "pnpm-lock.yaml":"javascript", "yarn.lock":"javascript", "go.mod":"go", "go.sum":"go", "Cargo.toml":"rust",
    "Cargo.lock":"rust", "pom.xml":"java", "build.gradle":"java", "build.gradle.kts":"kotlin", "CMakeLists.txt":"c-cpp",
    "Package.swift":"swift", "Package.resolved":"swift", "build.sbt":"scala", "pubspec.yaml":"dart", "pubspec.lock":"dart",
    "mix.exs":"elixir", "mix.lock":"elixir", "Gemfile":"ruby", "Gemfile.lock":"ruby", "composer.json":"php", "composer.lock":"php",
}


def _manifest_language(path: Path) -> str | None:
    if path.suffix.lower() in {".csproj", ".sln"}:
        return "csharp"
    return MANIFESTS.get(path.name)

def dependency_health(repo_path: str) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True); found = []
    for path in repository_files(repo):
        language = _manifest_language(path)
        if language:
            found.append((path, language))
    if not found:
        raise ToolHardFailure("Can't inspect dependencies — no supported dependency manifest was found in this repository.")
    lock_names = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.sum", "Cargo.lock", "Package.resolved", "pubspec.lock", "mix.lock", "Gemfile.lock", "composer.lock"}
    results = []
    for path, language in found:
        kind = "lockfile" if path.name in lock_names else "manifest"
        results.append(EvidenceItem("code_search", "dependency_inventory", f"{language} {kind} present: {path.name}", str(path.relative_to(repo))))
    results.append(EvidenceItem("code_search", "dependency_inventory", f"Found {len(found)} supported dependency file(s). This is inventory evidence only; run a package-native or security scanner for vulnerability claims.", str(repo)))
    return results
