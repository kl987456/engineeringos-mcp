"""Bounded, deterministic software-component inventory with Package URLs."""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import yaml

from ..evidence import EvidenceItem, ToolHardFailure
from ..filewalk import repository_files
from ..security import allowed_path

MAX_MANIFEST_BYTES = 5_000_000
MAX_COMPONENTS = 5_000
_VERSION_SPLIT = re.compile(r"\s*(?:===|==|~=|>=|<=|!=|>|<|\^|~)\s*")


@dataclass(frozen=True, order=True)
class Component:
    ecosystem: str
    name: str
    version: str
    manifest: str


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ToolHardFailure(f"Can't inventory dependencies — {path.name} exceeds the 5 MB manifest limit.")
    return path.read_text(encoding="utf-8", errors="replace")


def _clean_version(value: object) -> str:
    if value is None:
        return ""
    version = str(value).strip().strip('"\'')
    return version if len(version) <= 200 else ""


def _component(ecosystem: str, name: object, version: object, manifest: str) -> Component | None:
    clean_name = str(name).strip().strip('"\'') if name is not None else ""
    if not clean_name or len(clean_name) > 500 or any(char in clean_name for char in "\r\n\x00"):
        return None
    return Component(ecosystem, clean_name, _clean_version(version), manifest)


def _json_components(path: Path, rel: str) -> list[Component]:
    try:
        data = json.loads(_read(path))
    except json.JSONDecodeError:
        return []
    items: list[Component] = []
    if path.name == "package-lock.json" and isinstance(data, dict):
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for key, value in packages.items():
                if key and isinstance(value, dict):
                    item = _component("npm", value.get("name") or key.rsplit("node_modules/", 1)[-1], value.get("version"), rel)
                    if item: items.append(item)
        dependencies = data.get("dependencies", {})
        if not items and isinstance(dependencies, dict):
            for name, value in dependencies.items():
                item = _component("npm", name, value.get("version") if isinstance(value, dict) else None, rel)
                if item: items.append(item)
    elif path.name == "package.json" and isinstance(data, dict):
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            values = data.get(section, {})
            if isinstance(values, dict):
                for name, version in values.items():
                    item = _component("npm", name, version, rel)
                    if item: items.append(item)
    elif path.name == "composer.lock" and isinstance(data, dict):
        for section in ("packages", "packages-dev"):
            for value in data.get(section, []) if isinstance(data.get(section, []), list) else []:
                if isinstance(value, dict):
                    item = _component("composer", value.get("name"), value.get("version"), rel)
                    if item: items.append(item)
    elif path.name == "Package.resolved" and isinstance(data, dict):
        pins = data.get("pins") or (data.get("object", {}) or {}).get("pins", [])
        for value in pins if isinstance(pins, list) else []:
            if isinstance(value, dict):
                state = value.get("state", {}) if isinstance(value.get("state", {}), dict) else {}
                item = _component("swift", value.get("identity") or value.get("package"), state.get("version") or state.get("revision"), rel)
                if item: items.append(item)
    return items


def _toml_components(path: Path, rel: str) -> list[Component]:
    try:
        data = tomllib.loads(_read(path))
    except tomllib.TOMLDecodeError:
        return []
    items: list[Component] = []
    if path.name == "Cargo.lock":
        for value in data.get("package", []) if isinstance(data.get("package", []), list) else []:
            if isinstance(value, dict):
                item = _component("cargo", value.get("name"), value.get("version"), rel)
                if item: items.append(item)
    elif path.name == "pyproject.toml":
        project = data.get("project", {}) if isinstance(data.get("project", {}), dict) else {}
        for spec in project.get("dependencies", []) if isinstance(project.get("dependencies", []), list) else []:
            name, *rest = _VERSION_SPLIT.split(str(spec), maxsplit=1)
            item = _component("pypi", name.split("[")[0].strip(), rest[0] if rest else "", rel)
            if item: items.append(item)
        poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {}).get("dependencies", {})
        if isinstance(poetry, dict):
            for name, version in poetry.items():
                if name.lower() != "python":
                    item = _component("pypi", name, version if isinstance(version, str) else "", rel)
                    if item: items.append(item)
    return items


def _line_components(path: Path, rel: str) -> list[Component]:
    text = _read(path)
    items: list[Component] = []
    if path.name == "requirements.txt":
        for line in text.splitlines():
            spec = line.split("#", 1)[0].strip()
            if not spec or spec.startswith(("-", "http:", "https:", "git+")):
                continue
            name, *rest = _VERSION_SPLIT.split(spec, maxsplit=1)
            item = _component("pypi", name.split("[")[0].strip(), rest[0] if rest else "", rel)
            if item: items.append(item)
    elif path.name == "go.mod":
        for name, version in re.findall(r"(?m)^\s*(?:require\s+)?([\w.-]+(?:/[\w.-]+)+)\s+(v[^\s]+)", text):
            item = _component("golang", name, version, rel)
            if item: items.append(item)
    elif path.suffix.lower() == ".csproj":
        for attributes in re.findall(r"<PackageReference\b([^>]*)>", text, re.I):
            name = re.search(r"\bInclude=[\"']([^\"']+)[\"']", attributes, re.I)
            version = re.search(r"\bVersion=[\"']([^\"']+)[\"']", attributes, re.I)
            item = _component("nuget", name.group(1) if name else "", version.group(1) if version else "", rel)
            if item: items.append(item)
        for attributes, body in re.findall(r"<PackageReference\b([^>]*)>(.*?)</PackageReference>", text, re.I | re.S):
            name = re.search(r"\bInclude=[\"']([^\"']+)[\"']", attributes, re.I)
            version = re.search(r"<Version>([^<]+)</Version>", body, re.I)
            item = _component("nuget", name.group(1) if name else "", version.group(1) if version else "", rel)
            if item: items.append(item)
    elif path.name == "pom.xml":
        for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.I | re.S):
            group = re.search(r"<groupId>([^<]+)</groupId>", block, re.I)
            artifact = re.search(r"<artifactId>([^<]+)</artifactId>", block, re.I)
            version = re.search(r"<version>([^<]+)</version>", block, re.I)
            if artifact:
                item = _component("maven", f"{group.group(1)}:{artifact.group(1)}" if group else artifact.group(1), version.group(1) if version else "", rel)
                if item: items.append(item)
    elif path.name in {"build.gradle", "build.gradle.kts"}:
        for group, artifact, version in re.findall(r"[\"']([\w.-]+):([\w.-]+):([^\"']+)[\"']", text):
            item = _component("maven", f"{group}:{artifact}", version, rel)
            if item: items.append(item)
    elif path.name == "Gemfile.lock":
        for name, version in re.findall(r"(?m)^\s{4}([\w.-]+) \(([^)]+)\)", text):
            item = _component("gem", name, version, rel)
            if item: items.append(item)
    elif path.name == "mix.lock":
        for name, version in re.findall(r'"([\w.-]+)":\s*\{:hex,\s*:[\w.-]+,\s*"([^"]+)"', text):
            item = _component("hex", name, version, rel)
            if item: items.append(item)
    return items


def _yaml_components(path: Path, rel: str) -> list[Component]:
    try:
        data = yaml.safe_load(_read(path))
    except yaml.YAMLError:
        return []
    items: list[Component] = []
    if path.name == "pubspec.lock" and isinstance(data, dict):
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for name, value in packages.items():
                item = _component("pub", name, value.get("version") if isinstance(value, dict) else "", rel)
                if item: items.append(item)
    return items


def _purl(item: Component) -> str:
    name = item.name
    if item.ecosystem == "npm" and name.startswith("@") and "/" in name:
        namespace, name = name.split("/", 1)
        path = f"{quote(namespace, safe='')}/{quote(name, safe='')}"
    elif item.ecosystem in {"maven", "composer"} and (":" in name or "/" in name):
        separator = ":" if ":" in name else "/"
        namespace, name = name.split(separator, 1)
        path = f"{quote(namespace, safe='.')}/{quote(name, safe='.-_')}"
    elif item.ecosystem == "golang" and "/" in name:
        namespace, name = name.rsplit("/", 1)
        path = f"{quote(namespace, safe='./')}/{quote(name, safe='.-_')}"
    else:
        path = quote(name.lower() if item.ecosystem == "pypi" else name, safe=".-_")
    return f"pkg:{item.ecosystem}/{path}" + (f"@{quote(item.version, safe='.-_+~') }" if item.version else "")


def _inventory_components(repo: Path) -> tuple[set[Component], int]:
    supported = {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "go.mod", "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile.lock", "composer.lock", "pubspec.lock", "mix.lock", "Package.resolved"}
    components: set[Component] = set()
    manifests = 0
    for path in repository_files(repo):
        if path.name not in supported and path.suffix.lower() != ".csproj":
            continue
        manifests += 1
        rel = path.relative_to(repo).as_posix()
        if path.suffix == ".json" or path.name in {"package-lock.json", "composer.lock", "Package.resolved"}:
            parsed = _json_components(path, rel)
        elif path.suffix == ".toml" or path.name == "Cargo.lock":
            parsed = _toml_components(path, rel)
        elif path.suffix in {".yaml", ".yml"} or path.name == "pubspec.lock":
            parsed = _yaml_components(path, rel)
        else:
            parsed = _line_components(path, rel)
        components.update(parsed)
        if len(components) > MAX_COMPONENTS:
            raise ToolHardFailure(f"Can't inventory dependencies — more than {MAX_COMPONENTS} unique components were found. Narrow the repository scope.")
    return components, manifests


def software_inventory(repo_path: str) -> list[EvidenceItem]:
    repo = allowed_path(repo_path, must_be_dir=True)
    components, manifests = _inventory_components(repo)
    if manifests == 0:
        raise ToolHardFailure("Can't inventory dependencies — no supported manifest or lockfile was found.")
    if not components:
        raise ToolHardFailure("Can't inventory dependencies — supported manifests were found but no component coordinates could be parsed.")
    return [
        EvidenceItem("code_search", "software_inventory", f"{item.ecosystem} component {item.name}{'@' + item.version if item.version else ''}", f"{_purl(item)} | {item.manifest}")
        for item in sorted(components)
    ]


def cyclonedx_sbom(repo_path: str) -> tuple[dict, EvidenceItem]:
    """Return a deterministic CycloneDX 1.6 component document without network enrichment."""
    repo = allowed_path(repo_path, must_be_dir=True)
    components, manifests = _inventory_components(repo)
    if manifests == 0 or not components:
        raise ToolHardFailure("Can't build an SBOM — no parseable components were found in supported manifests or lockfiles.")
    grouped: dict[tuple[str, str, str], set[str]] = {}
    for item in components:
        grouped.setdefault((item.ecosystem, item.name, item.version), set()).add(item.manifest)
    bom_components = []
    for ecosystem, name, version in sorted(grouped):
        item = Component(ecosystem, name, version, sorted(grouped[(ecosystem, name, version)])[0])
        purl = _purl(item)
        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "purl": purl,
            "properties": [{"name": "engineeringos:manifests", "value": ",".join(sorted(grouped[(ecosystem, name, version)]))}],
        }
        if version:
            component["version"] = version
        bom_components.append(component)
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": bom_components}
    evidence = EvidenceItem("code_search", "cyclonedx_sbom", f"Generated a deterministic CycloneDX 1.6 inventory with {len(bom_components)} component(s) from {manifests} manifest(s); no vulnerability enrichment was performed.", str(repo))
    return bom, evidence
