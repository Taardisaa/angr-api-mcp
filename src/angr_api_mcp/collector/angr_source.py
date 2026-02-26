"""Collect and enumerate Python source files from angr and angr-doc repos."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from angr_api_mcp.config import Config
from angr_api_mcp.extractor.models import SourceFile, TrustLevel
from angr_api_mcp.parser.python_parser import find_class_names, parse_python

logger = logging.getLogger(__name__)

TRUST_MAP: dict[str, TrustLevel] = {
    "highest": TrustLevel.HIGHEST,
    "high": TrustLevel.HIGH,
    "medium": TrustLevel.MEDIUM,
}


def clone_repo(url: str, target: Path, depth: int = 1) -> Path:
    """Shallow-clone a git repo into target; skip if already present."""
    if target.exists() and any(target.iterdir()):
        logger.info("Repo already exists at %s, skipping clone", target)
        return target

    logger.info("Cloning %s (depth=%d) into %s ...", url, depth, target)
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", str(depth), url, str(target)],
        check=True,
    )
    return target


def detect_angr_version(angr_root: Path) -> str:
    """Read the angr version from angr/__init__.py or pyproject.toml.

    Returns the version string (e.g. "9.2.105") or "unknown" if not found.
    """
    # Try angr/angr/__init__.py
    init_file = angr_root / "angr" / "__init__.py"
    if init_file.exists():
        try:
            for line in init_file.read_text(encoding="utf-8").splitlines():
                if "__version__" in line and "=" in line:
                    # e.g. __version__ = "9.2.105"
                    val = line.split("=", 1)[1].strip().strip('"\'')
                    if val:
                        return val
        except Exception:
            pass

    # Try pyproject.toml
    pyproject = angr_root / "pyproject.toml"
    if pyproject.exists():
        try:
            for line in pyproject.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("version") and "=" in line:
                    val = line.split("=", 1)[1].strip().strip('"\'')
                    if val:
                        return val
        except Exception:
            pass

    return "unknown"


def validate_angr_root(path: Path) -> bool:
    """Check that a path looks like an angr source tree."""
    return (path / "angr" / "__init__.py").exists()


def validate_angr_doc_root(path: Path) -> bool:
    """Check that a path looks like an angr-doc source tree."""
    return (path / "examples").is_dir()


def enumerate_python_files(
    angr_root: Path | None,
    angr_doc_root: Path | None,
    config: Config,
) -> list[SourceFile]:
    """Walk both repos and return Python files ranked by trust.

    Files are deduplicated: a file matching a higher-trust pattern won't
    be included again under a lower-trust one.
    """
    seen_paths: set[Path] = set()
    results: list[SourceFile] = []

    repo_roots = {
        "angr_doc": angr_doc_root,
        "angr": angr_root,
    }

    for repo_key, glob_pattern, trust_str, category in config.scan_dirs:
        root = repo_roots.get(repo_key)
        if root is None:
            continue

        trust = TRUST_MAP[trust_str]
        pattern = glob_pattern.rstrip("/") + "/**/*.py"
        matched = sorted(root.glob(pattern))

        for path in matched:
            # Skip __pycache__, compiled files, conftest helpers
            if "__pycache__" in path.parts:
                continue
            if path.suffix != ".py":
                continue
            resolved = path.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            results.append(SourceFile(path=path, trust_level=trust, category=category))

    if config.max_files is not None:
        results = results[: config.max_files]

    logger.info(
        "Found %d Python files (%d highest, %d high, %d medium trust)",
        len(results),
        sum(1 for f in results if f.trust_level == TrustLevel.HIGHEST),
        sum(1 for f in results if f.trust_level == TrustLevel.HIGH),
        sum(1 for f in results if f.trust_level == TrustLevel.MEDIUM),
    )
    return results


def build_known_angr_classes(angr_root: Path) -> set[str]:
    """Build a set of known angr class names by scanning the source tree.

    Uses tree-sitter class definition queries to find class names without
    requiring angr to be installed.
    """
    class_names: set[str] = set()
    angr_pkg = angr_root / "angr"

    if not angr_pkg.is_dir():
        logger.warning("angr package directory not found at %s", angr_pkg)
        return class_names

    for py_file in angr_pkg.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        try:
            source = py_file.read_bytes()
            tree = parse_python(source)
            names = find_class_names(tree, source)
            class_names.update(names)
        except Exception as e:
            logger.debug("Could not scan %s for class names: %s", py_file, e)

    logger.info("Built known angr class set: %d classes", len(class_names))
    return class_names
