"""Helpers for locating challenge config roots on disk."""
from pathlib import Path
from typing import Iterator, Optional


CONFIG_FILENAMES = ("challenge.yaml", "challenge.yml")
COMPOSE_FILENAMES = ("docker-compose.yaml", "docker-compose.yml")
IGNORED_ROOT_NAMES = {"__MACOSX", ".DS_Store", "Thumbs.db"}


def _find_existing_file(base_dir: Path, filenames: tuple[str, ...]) -> Optional[Path]:
    """Return the first matching file under a directory."""
    for name in filenames:
        candidate = base_dir / name
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def get_challenge_config_path(challenge_dir: Path) -> Optional[Path]:
    """Return the challenge config file path, supporting yaml and yml."""
    return _find_existing_file(challenge_dir, CONFIG_FILENAMES)


def get_challenge_compose_path(challenge_dir: Path) -> Optional[Path]:
    """Return the docker compose file path, supporting yaml and yml."""
    return _find_existing_file(challenge_dir, COMPOSE_FILENAMES)


def is_challenge_root(challenge_dir: Path) -> bool:
    """Return whether a directory looks like a runnable challenge root."""
    return bool(
        challenge_dir.exists()
        and challenge_dir.is_dir()
        and not challenge_dir.is_symlink()
        and get_challenge_config_path(challenge_dir)
        and get_challenge_compose_path(challenge_dir)
    )


def iter_visible_children(directory: Path) -> Iterator[Path]:
    """Yield non-hidden child paths that are safe to inspect."""
    try:
        children = sorted(directory.iterdir(), key=lambda item: item.name.lower())
    except (OSError, PermissionError):
        return

    for item in children:
        if item.is_symlink():
            continue
        if item.name in IGNORED_ROOT_NAMES:
            continue
        if item.name.startswith("."):
            continue
        yield item


def find_challenge_root(base_dir: Path, max_depth: int = 4) -> Optional[Path]:
    """
    Find the single usable challenge root inside a directory tree.

    Returns the matching directory when exactly one candidate exists, otherwise
    returns None so the caller can surface a clear error or fallback.
    """
    if not base_dir.exists() or not base_dir.is_dir() or base_dir.is_symlink():
        return None

    if is_challenge_root(base_dir):
        return base_dir

    candidates: list[Path] = []
    queue: list[tuple[Path, int]] = [(base_dir, 0)]
    seen: set[Path] = set()

    while queue:
        current_dir, depth = queue.pop(0)
        try:
            resolved_current = current_dir.resolve()
        except OSError:
            continue
        if resolved_current in seen:
            continue
        seen.add(resolved_current)

        if depth >= max_depth:
            continue

        for child in iter_visible_children(current_dir):
            if not child.is_dir():
                continue
            if is_challenge_root(child):
                candidates.append(child)
                continue
            queue.append((child, depth + 1))

    if len(candidates) == 1:
        return candidates[0]
    return None
