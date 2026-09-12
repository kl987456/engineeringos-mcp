"""Allow-listed polyglot test-runner discovery and bounded result parsing."""
from __future__ import annotations

import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from .audit import redact_sensitive
from .evidence import EvidenceItem

MAX_OUTPUT_BYTES = 1_000_000
MAX_EVIDENCE_ITEMS = 1_000
MAX_RUNNERS = 16
RUNNER_NAMES = frozenset({
    "pytest", "pnpm", "yarn", "npm", "go", "cargo", "dotnet", "maven",
    "gradle", "swift", "sbt", "dart", "mix", "rspec", "phpunit", "ctest",
})


@dataclass(frozen=True)
class TestRunner:
    name: str
    command: tuple[str, ...]
    manifest: str
    available: bool
    parser: str = "generic"


def _package_has_test(repo: Path) -> bool:
    try:
        package = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    script = (package.get("scripts") or {}).get("test") if isinstance(package, dict) else None
    return isinstance(script, str) and bool(script.strip()) and "no test specified" not in script.lower()


def detect(repo: Path) -> list[TestRunner]:
    """Detect only fixed, reviewed commands; repository content never becomes a command."""
    runners: list[TestRunner] = []
    if (repo / "tests").exists() or any(repo.glob("test_*.py")) or any(repo.glob("*_test.py")):
        runners.append(TestRunner("pytest", (sys.executable, "-m", "pytest", "-v"), "Python tests", True, "pytest"))
    if (repo / "package.json").is_file() and _package_has_test(repo):
        if (repo / "pnpm-lock.yaml").is_file():
            runners.append(TestRunner("pnpm", ("pnpm", "test", "--offline"), "pnpm-lock.yaml", shutil.which("pnpm") is not None))
        elif (repo / "yarn.lock").is_file():
            runners.append(TestRunner("yarn", ("yarn", "test", "--offline"), "yarn.lock", shutil.which("yarn") is not None))
        else:
            runners.append(TestRunner("npm", ("npm", "test", "--ignore-scripts"), "package.json", shutil.which("npm") is not None, "node"))
    if (repo / "go.mod").is_file():
        runners.append(TestRunner("go", ("go", "test", "-json", "-count=1", "./..."), "go.mod", shutil.which("go") is not None, "go-json"))
    if (repo / "Cargo.toml").is_file():
        command = ["cargo", "test", "--offline", "--no-fail-fast"]
        if (repo / "Cargo.lock").is_file():
            command.insert(2, "--locked")
        runners.append(TestRunner("cargo", tuple(command), "Cargo.toml", shutil.which("cargo") is not None))
    dotnet_manifest = next(iter(sorted(repo.glob("*.sln"))), None) or next(iter(sorted(repo.glob("*.csproj"))), None)
    if dotnet_manifest:
        runners.append(TestRunner("dotnet", ("dotnet", "test", "--no-restore", "--nologo", "--verbosity", "minimal"), dotnet_manifest.name, shutil.which("dotnet") is not None))
    if (repo / "pom.xml").is_file():
        runners.append(TestRunner("maven", ("mvn", "--offline", "--batch-mode", "test"), "pom.xml", shutil.which("mvn") is not None))
    if (repo / "build.gradle").is_file() or (repo / "build.gradle.kts").is_file():
        manifest = "build.gradle.kts" if (repo / "build.gradle.kts").is_file() else "build.gradle"
        runners.append(TestRunner("gradle", ("gradle", "--offline", "test", "--console=plain"), manifest, shutil.which("gradle") is not None))
    if (repo / "Package.swift").is_file():
        runners.append(TestRunner("swift", ("swift", "test", "--skip-update"), "Package.swift", shutil.which("swift") is not None))
    if (repo / "build.sbt").is_file():
        runners.append(TestRunner("sbt", ("sbt", "-batch", "-offline", "test"), "build.sbt", shutil.which("sbt") is not None))
    if (repo / "pubspec.yaml").is_file():
        runners.append(TestRunner("dart", ("dart", "test", "--reporter", "json"), "pubspec.yaml", shutil.which("dart") is not None))
    if (repo / "mix.exs").is_file():
        runners.append(TestRunner("mix", ("mix", "test", "--no-color"), "mix.exs", shutil.which("mix") is not None))
    if (repo / "Gemfile").is_file():
        runners.append(TestRunner("rspec", ("bundle", "exec", "rspec", "--format", "progress", "--no-color"), "Gemfile", shutil.which("bundle") is not None))
    if (repo / "composer.json").is_file() and (repo / "vendor" / "bin" / "phpunit").exists():
        runners.append(TestRunner("phpunit", ("php", "vendor/bin/phpunit", "--colors=never"), "composer.json", shutil.which("php") is not None))
    if (repo / "CTestTestfile.cmake").is_file() or (repo / "build" / "CTestTestfile.cmake").is_file():
        directory = "build" if (repo / "build" / "CTestTestfile.cmake").is_file() else "."
        runners.append(TestRunner("ctest", ("ctest", "--test-dir", directory, "--output-on-failure"), "CTestTestfile.cmake", shutil.which("ctest") is not None))
    return runners[:MAX_RUNNERS]


def parse_pytest(output: str) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for line in output.splitlines():
        line = line.strip()
        if " PASSED" in line or " FAILED" in line or " ERROR" in line:
            status = "PASSED" if " PASSED" in line else "FAILED" if " FAILED" in line else "ERROR"
            test_name = line.split(" ")[0]
            items.append(EvidenceItem("test_result", "pytest", f"{status}: {test_name}", test_name))
    return items


def parse_go(output: str) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    seen: set[tuple[str, str, str]] = set()
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        action, test, package = event.get("Action"), event.get("Test"), event.get("Package", "go")
        if action not in {"pass", "fail", "skip"} or not isinstance(test, str) or not isinstance(package, str):
            continue
        identity = (action, package, test)
        if identity not in seen:
            seen.add(identity)
            items.append(EvidenceItem("test_result", "go-test", f"{action.upper()}: {test}", f"{package}::{test}"))
    return items


def parse_result(runner: TestRunner, output: str, returncode: int) -> list[EvidenceItem]:
    if runner.parser == "pytest":
        items = parse_pytest(output)
    elif runner.parser == "go-json":
        items = parse_go(output)
    else:
        items = []
    if items:
        return items[:MAX_EVIDENCE_ITEMS]
    generic: list[EvidenceItem] = []
    for raw in output.splitlines():
        match = re.match(r"^(PASS|FAIL)\s+(.+)$", raw.strip())
        if match:
            status = "PASSED" if match.group(1) == "PASS" else "FAILED"
            ref = redact_sensitive(match.group(2), 300)
            generic.append(EvidenceItem("test_result", runner.name, f"{status}: {ref}", ref))
    if generic:
        return generic[:MAX_EVIDENCE_ITEMS]
    lines = [redact_sensitive(line, 300) for line in output.splitlines() if line.strip()]
    detail = " | ".join(lines[-3:]) or "no test output"
    status = "PASSED" if returncode == 0 else "FAILED"
    return [EvidenceItem("test_result", runner.name, f"{status}: {runner.name} exited {returncode}; {detail}", runner.manifest)]
