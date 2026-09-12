from __future__ import annotations
from collections import Counter
from ..evidence import EvidenceChain, EvidenceItem, ToolHardFailure
from .. import indexer
from ..security import allowed_path
from ..filewalk import repository_files

LANGUAGES = indexer.LANGUAGES

def repo_overview(repo_path: str) -> dict:
    repo = allowed_path(repo_path, must_be_dir=True)
    chain = EvidenceChain(question=f"What is the current shape of {repo}?")
    counts = Counter(); files = 0; tests = 0
    for path in repository_files(repo):
        files += 1; counts[LANGUAGES.get(path.suffix.lower(), "other")] += 1
        if path.name.startswith("test_") and path.suffix == ".py" or path.name.endswith("_test.go") or path.name.endswith(".spec.ts"):
            tests += 1
    chain.evidence.append(EvidenceItem("code_search", "repository", f"{files} candidate files; languages: {dict(counts)}", str(repo)))
    chain.evidence.append(EvidenceItem("test_result", "repository", f"Detected {tests} test file(s)", str(repo / "tests")))
    chain.evidence.append(indexer.freshness(str(repo)))
    for name in (".git", "Dockerfile", "pyproject.toml", "package.json", "requirements.txt", "SECURITY.md"):
        chain.evidence.append(EvidenceItem("code_search", "repository", f"{name}: {'present' if (repo / name).exists() else 'not present'}", str(repo / name)))
    return chain.to_dict()
