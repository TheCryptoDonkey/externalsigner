import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "data",
    "docs",
    "node_modules",
    "output",
    "tmp",
}
TEXT_SUFFIXES = {
    "",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".py",
    ".svg",
    ".toml",
    ".yaml",
    ".yml",
}


def test_release_metadata_has_one_owner_version_and_repository():
    config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert config["version"] == "0.1.0"
    assert config["contributors"] == [
        {
            "name": "The Crypto Donkey",
            "uri": "https://github.com/TheCryptoDonkey",
            "role": "Developer",
        }
    ]
    assert manifest == {
        "repos": [
            {
                "id": "externalsigner",
                "organisation": "TheCryptoDonkey",
                "repository": "externalsigner",
            }
        ]
    }
    assert re.search(r'^version = "0\.1\.0"$', pyproject, re.MULTILINE)
    assert 'authors = [{ name = "The Crypto Donkey" }]' in pyproject
    assert 'Repository = "https://github.com/TheCryptoDonkey/externalsigner"' in pyproject


def test_licence_funding_and_document_location_policy():
    licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
    funding = (ROOT / ".github" / "FUNDING.yml").read_text(encoding="utf-8")
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()

    assert licence.startswith("MIT License\n\nCopyright (c) 2026 The Crypto Donkey\n")
    assert funding.splitlines() == ["github: TheCryptoDonkey", "ko_fi: brays"]
    assert "docs/" in ignored
    assert not any((ROOT / "docs").iterdir())
    for name in (
        "ADMIN.md",
        "ARCHITECTURE.md",
        "HOST_DEPENDENCIES.md",
        "INTEGRATION.md",
        "QUICKSTART.md",
        "RELEASE_CHECKLIST.md",
        "VERIFICATION.md",
    ):
        assert (ROOT / name).is_file()


def test_public_source_contains_no_prohibited_attribution():
    prohibited = ("Dar" + "ren Bow" + "les", "Ep" + "ona", "Forge" + "Sworn")
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        for value in prohibited:
            assert value.casefold() not in text.casefold(), f"prohibited attribution in {path}"
