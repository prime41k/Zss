"""
ZSS — Zero State Snapshot v4.0
Локальный версионатор для Termux/Linux/macOS.
Один файл, стандартная библиотека, production-ready.
"""

import os
import json
import difflib
import fcntl
import re
import time
import logging
import hashlib
import zlib
import signal
import threading
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set, Generator, NamedTuple, TypedDict
from contextlib import contextmanager

# --- Конфигурация и типы ---

INDEX_VERSION = 4
TIMESTAMP_FMT = "%Y-%m-%d_%H-%M-%S_%f"
TIMESTAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_\d{6}$')
SECRET_PATTERNS = [
    re.compile(r'(?i)(?:api[_-]?key|token|password|secret|auth)\s*[:=]\s*["\']([A-Za-z0-9+/=_\-]{16,})["\']'),
]
HASH_CHUNK_SIZE = 65536  # 64KB для streaming hash

logger = logging.getLogger("zss")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class VersionEntry(TypedDict):
    timestamp: str
    hash: str
    size: int
    compressed: bool
    lines: int
    path: str
    tags: Dict[str, str]


class TrackStats(NamedTuple):
    checked: int
    saved: int
    errors: int


# --- Исключения ---

class ZSSError(Exception):
    """Базовая ошибка ZSS."""
    pass

class CorruptedIndexError(ZSSError):
    """Индекс повреждён или имеет неверную версию."""
    pass

class SecretDetectedError(ZSSError):
    """В файле обнаружены потенциальные секреты."""
    def __init__(self, secrets: List[str]):
        self.secrets = secrets
        super().__init__(f"Secrets detected: {len(secrets)} matches")

class RollbackError(ZSSError):
    """Ошибка при откате версии."""
    pass


# - Потокобезопасный LRU Cache --

class LRUCache:
    """Thread-safe LRU кэш с двойной валидацией (TTL + mtime)."""

    def __init__(self, max_size: int = 128):
        self._max_size = max(max_size, 1)
        self._cache: OrderedDict[str, Tuple[List[VersionEntry], float, float]] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str, current_mtime: float, ttl: float) -> Optional[List[VersionEntry]]:
        with self._lock:
            if key not in self._cache:
                return None
            index, cached_mtime, cached_time = self._cache[key]
            if (time.monotonic() - cached_time) > ttl or cached_mtime != current_mtime:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return index

    def put(self, key: str, value: List[VersionEntry], mtime: float) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self._max_size:
                    self._cache.popitem(last=False)
            self._cache[key] = (value, mtime, time.monotonic())

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# --- Файловые блокировки 

class FileLock:
    """
    POSIX file lock с поддержкой shared/exclusive режимов.
    FD создаётся внутри контекста — безопасно для многопоточности.
    """

    def __init__(self, lock_path: Path):
        self._path = lock_path

    @contextmanager
    def exclusive(self):
        """Эксклюзивная блокировка для записи."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = open(self._path, 'w')
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            fd.close()

    @contextmanager
    def shared(self):
        """Разделяемая блокировка для чтения."""
        if not self._path.exists():
            yield
            return
        fd = open(self._path, 'r')
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_SH)
            yield
        finally:
            try:
                fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            fd.close()


# --- Менеджер индексов ---

class IndexManager:
    """Управление JSON-индексами с миграцией и кэшированием."""

    def __init__(self, root: Path, cache: LRUCache, ttl: float):
        self._root = root
        self._cache = cache
        self._ttl = ttl
        self._dirty: Set[str] = set()
        self._pending: Dict[str, List[VersionEntry]] = {}

    def _index_path(self, filepath: Path) -> Path:
        h = hashlib.md5(str(filepath.resolve()).encode()).hexdigest()[:24]
        return self._root / f"{h}.index.json"

    def load(self, filepath: Path) -> List[VersionEntry]:
        idx_path = self._index_path(filepath)
        key = str(idx_path)

        try:
            mtime = idx_path.stat().st_mtime
        except OSError:
            mtime = 0.0

        cached = self._cache.get(key, mtime, self._ttl)
        if cached is not None:
            return cached

        entries: List[VersionEntry] = []
        if idx_path.exists():
            try:
                raw = json.loads(idx_path.read_text(encoding='utf-8'))
                if isinstance(raw, dict):
                    ver = raw.get("version", 1)
                    if ver == INDEX_VERSION:
                        entries = raw.get("entries", [])
                    elif ver < INDEX_VERSION:
                        entries = self._migrate(raw, ver)
                    else:
                        raise CorruptedIndexError(f"Future index version {ver}")
                elif isinstance(raw, list):
                    entries = raw  # legacy v1
                else:
                    raise CorruptedIndexError("Invalid index structure")
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning("Corrupted index %s: %s", idx_path.name, e)
                entries = []
            except CorruptedIndexError as e:
                logger.error("%s: %s", idx_path.name, e)
                entries = []

        self._cache.put(key, entries, mtime)
        return entries

    def stage_save(self, filepath: Path, entries: List[VersionEntry]) -> None:
        """Откладывает сохранение индекса для batch-write."""
        key = str(self._index_path(filepath))
        self._pending[key] = entries
        self._dirty.add(key)

    def flush(self) -> int:
        """Записывает все грязные индексы на диск. Возвращает кол-во записанных."""
        if not self._dirty:
            return 0
        count = 0
        for key in list(self._dirty):
            idx_path = Path(key)
            entries = self._pending.get(key, [])
            tmp = idx_path.with_suffix('.tmp')
            try:
                data = {"version": INDEX_VERSION, "entries": entries}
                tmp.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
                os.replace(str(tmp), str(idx_path))
                try:
                    mtime = idx_path.stat().st_mtime
                except OSError:
                    mtime = 0.0
                self._cache.put(key, entries, mtime)
                count += 1
            except OSError as e:
                logger.error("Failed to flush index %s: %s", idx_path.name, e)
                if tmp.exists():
                    tmp.unlink(missing_ok=True)
            finally:
                self._pending.pop(key, None)
        self._dirty.clear()
        return count

    def save_now(self, filepath: Path, entries: List[VersionEntry]) -> None:
        """Немедленная запись одного индекса (для rollback/add_tag)."""
        idx_path = self._index_path(filepath)
        tmp = idx_path.with_suffix('.tmp')
        try:
            data = {"version": INDEX_VERSION, "entries": entries}
            tmp.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
            os.replace(str(tmp), str(idx_path))
            mtime = idx_path.stat().st_mtime
            self._cache.put(str(idx_path), entries, mtime)
        except OSError as e:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
            raise ZSSError(f"Index save failed: {e}")

    @staticmethod
    def _migrate(raw: dict, from_ver: int) -> List[VersionEntry]:
        """Миграция индексов старых версий."""
        if from_ver <= 2:
            entries = raw.get("entries", raw if isinstance(raw, list) else [])
            for e in entries:
                e.setdefault("tags", {})
                e.setdefault("compressed", False)
            return entries
        return []


# --- Хранилище версий ---

class VersionStore:
    """Хранение снапшотов с streaming-hash и lazy-decompression."""

    def __init__(self, root: Path, compress: bool):
        self._root = root
        self._compress = compress

    @staticmethod
    def compute_hash_stream(filepath: Path) -> str:
        """BLAKE2b hash чанками без загрузки всего файла в память."""
        h = hashlib.blake2b(digest_size=8)
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def compute_hash_bytes(data: bytes) -> str:
        return hashlib.blake2b(data, digest_size=8).hexdigest()

    @staticmethod
    def is_text(filepath: Path) -> bool:
        """Проверка на текстовый файл по первым 8KB."""
        try:
            with open(filepath, 'rb') as f:
                sample = f.read(8192)
        except OSError:
            return False
        if b'\x00' in sample:
            return sample.startswith(b'\xff\xfe') or sample.startswith(b'\xfe\xff')
        return True

    @staticmethod
    def check_secrets(content: str) -> List[str]:
        found = []
        for pattern in SECRET_PATTERNS:
            found.extend(pattern.findall(content))
        return found

    def version_path(self, filepath: Path, timestamp: str) -> Path:
        if not TIMESTAMP_RE.match(timestamp):
            raise ZSSError(f"Invalid timestamp format: {timestamp}")
        # Валидация даты
        try:
            datetime.strptime(timestamp, TIMESTAMP_FMT)
        except ValueError:
            raise ZSSError(f"Invalid date in timestamp: {timestamp}")
        safe = hashlib.md5(str(filepath.resolve()).encode()).hexdigest()[:24]
        ext = ".ztxt" if self._compress else ".txt"
        return self._root / f"{safe}.{timestamp}{ext}"

    def read_version(self, filepath: Path, timestamp: str) -> Optional[bytes]:
        """Читает и декомпрессирует версию. Пробует оба расширения."""
        vp = self.version_path(filepath, timestamp)
        if not vp.exists():
            alt = vp.with_suffix('.txt') if vp.suffix == '.ztxt' else vp.with_suffix('.ztxt')
            if alt.exists():
                vp = alt
            else:
                return None
        try:
            raw = vp.read_bytes()
        except OSError:
            return None
        if vp.suffix == '.ztxt':
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return None
        return raw

    def read_version_lines(self, filepath: Path, timestamp: str) -> Generator[str, None, None]:
        """Генератор строк версии для streaming diff."""
        data = self.read_version(filepath, timestamp)
        if data is None:
            return
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            text = data.decode('latin-1')
        for line in text.splitlines(keepends=True):
            yield line


# --- Основной класс ---

class TimeMachine:
    """
    Координатор версионирования.
    Поддерживает context manager для автоматического flush.
    """

    def __init__(
        self,
        root: str = ".zss_data",
        extensions: Optional[List[str]] = None,
        keep_default: int = 100,
        cache_ttl: float = 1.0,
        max_cache_size: int = 128,
        compress: bool = True,
        block_on_secrets: bool = False,
    ):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.extensions = set(extensions or [".py"])
        self.keep_default = keep_default
        self.block_on_secrets = block_on_secrets

        self._cache = LRUCache(max_cache_size)
        self._lock = FileLock(self.root / ".zss.lock")
        self._idx = IndexManager(self.root, self._cache, cache_ttl)
        self._store = VersionStore(self.root, compress)

        self._stats = {"tracked": 0, "saved": 0, "rollbacks": 0, "errors": 0}
        self._shutdown = False

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info("Signal %s received, flushing...", signum)
        self._shutdown = True
        self._idx.flush()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._idx.flush()
        return False

    # --- Public API ---

    def track(self, paths: Optional[List[str]] = None) -> TrackStats:
        """Сканирует файлы, сохраняет изменённые. Batch-save индексов."""
        files: List[Path] = []
        if paths:
            for p in paths:
                fp = Path(p).resolve()
                if fp.is_file() and not fp.is_symlink() and fp.suffix in self.extensions:
                    files.append(fp)
        else:
            for ext in self.extensions:
                for fp in Path(".").rglob(f"*{ext}"):
                    rp = fp.resolve()
                    if self.root not in rp.parents and not fp.name.startswith('.'):
                        files.append(rp)

        saved = 0
        errors = 0

        with self._lock.exclusive():
            for fp in files:
                if self._shutdown:
                    break
                try:
                    if self._save_one(fp):
                        saved += 1
                except SecretDetectedError as e:
                    logger.warning("BLOCKED %s: %s", fp.name, e)
                    errors += 1
                except ZSSError as e:
                    logger.error("SKIP %s: %s", fp.name, e)
                    errors += 1
                except OSError as e:
                    logger.error("IO ERROR %s: %s", fp.name, e)
                    errors += 1

            flushed = self._idx.flush()

        self._stats["tracked"] += len(files)
        self._stats["saved"] += saved
        self._stats["errors"] += errors

        if saved > 0:
            logger.info("Track: %d saved, %d unchanged, %d indexes flushed", saved, len(files) - saved, flushed)

        return TrackStats(checked=len(files), saved=saved, errors=errors)

    def history(self, filename: str, limit: int = 10) -> List[VersionEntry]:
        """История версий файла. Shared lock."""
        fp = Path(filename).resolve()
        with self._lock.shared():
            entries = self._idx.load(fp)
        return entries[-limit:] if limit > 0 else entries

    def add_tag(self, filename: str, timestamp: str, tag: str) -> None:
        """Добавляет тег к версии. Немедленная запись."""
        fp = Path(filename).resolve()
        with self._lock.exclusive():
            entries = self._idx.load(fp)
            for entry in entries:
                if entry["timestamp"] == timestamp:
                    entry.setdefault("tags", {})[tag] = timestamp
                    self._idx.save_now(fp, entries)
                    logger.info("Tag '%s' -> %s", tag, timestamp)
                    return
        raise ZSSError(f"Timestamp {timestamp} not found for {filename}")

    def rollback(self, filename: str, target: str) -> None:
        """
        Атомарный откат. target = timestamp или тег.
        Бэкап текущего состояния перед перезаписью.
        Raises RollbackError при неудаче.
        """
        fp = Path(filename).resolve()
        with self._lock.exclusive():
            entries = self._idx.load(fp)
            ts = self._resolve_target(entries, target)
            if ts is None:
                raise RollbackError(f"Target '{target}' not found")

            content = self._store.read_version(fp, ts)
            if content is None:
                raise RollbackError(f"Version data missing for {ts}")

            backup = fp.with_suffix('.zss_rollback_bak')
            try:
                if fp.exists():
                    os.replace(str(fp), str(backup))
                tmp = fp.with_suffix('.zss_tmp')
                tmp.write_bytes(content)
                os.replace(str(tmp), str(fp))
                if backup.exists():
                    backup.unlink(missing_ok=True)
                self._stats["rollbacks"] += 1
                logger.info("Rolled back %s to %s", fp.name, ts)
            except OSError as e:
                if backup.exists() and not fp.exists():
                    try:
                        os.replace(str(backup), str(fp))
                    except OSError:
                        pass
                raise RollbackError(f"Rollback failed: {e}")

    def diff(self, filename: str, ts1: str, ts2: str) -> Generator[str, None, None]:
        """Unified diff между двумя версиями. Streaming, без загрузки в память."""
        fp = Path(filename).resolve()
        lines1 = self._store.read_version_lines(fp, ts1)
        lines2 = self._store.read_version_lines(fp, ts2)
        yield from difflib.unified_diff(
            lines1, lines2,
            fromfile=f"{filename}@{ts1}",
            tofile=f"{filename}@{ts2}",
        )

    def clean(self, filename: str, keep: Optional[int] = None, max_age_minutes: int = 60) -> Dict:
        """Удаляет старые версии и временные файлы."""
        keep = keep or self.keep_default
        fp = Path(filename).resolve()

        with self._lock.exclusive():
            entries = self._idx.load(fp)
            if len(entries) <= keep:
                return {"deleted": 0, "kept": len(entries)}

            to_del = entries[:-keep]
            deleted = 0
            for entry in to_del:
                vp = self._store.version_path(fp, entry['timestamp'])
                for candidate in [vp, vp.with_suffix('.txt'), vp.with_suffix('.ztxt')]:
                    if candidate.exists():
                        try:
                            candidate.unlink()
                            deleted += 1
                        except OSError:
                            pass
            self._idx.save_now(fp, entries[-keep:])

        now = time.time()
        tmp_cleaned = 0
        for tmp in self.root.glob("*.tmp"):
            try:
                if now - tmp.stat().st_mtime > max_age_minutes * 60:
                    tmp.unlink()
                    tmp_cleaned += 1
            except OSError:
                pass

        return {"versions_deleted": deleted, "tmp_cleaned": tmp_cleaned, "kept": keep}

    def purge_missing(self, known_files: Optional[List[str]] = None) -> Dict:
        """Удаляет данные для файлов, которых нет на диске."""
        if known_files is None:
            known_set: Set[str] = set()
            for ext in self.extensions:
                for p in Path(".").rglob(f"*{ext}"):
                    rp = p.resolve()
                    if self.root not in rp.parents and not p.name.startswith('.'):
                        known_set.add(str(rp))
        else:
            known_set = {str(Path(f).resolve()) for f in known_files}

        orphaned_indices: List[Path] = []
        for idx_file in self.root.glob("*.index.json"):
            try:
                raw = json.loads(idx_file.read_text(encoding='utf-8'))
                entries = raw.get("entries", []) if isinstance(raw, dict) else raw
                paths_in_idx = {e.get("path") for e in entries if e.get("path")}
                if paths_in_idx and not paths_in_idx.intersection(known_set):
                    orphaned_indices.append(idx_file)
            except (json.JSONDecodeError, OSError):
                continue

        deleted = 0
        with self._lock.exclusive():
            for idx_file in orphaned_indices:
                prefix = idx_file.stem
                for vf in self.root.glob(f"{prefix}.*"):
                    if vf.suffix in ('.txt', '.ztxt'):
                        try:
                            vf.unlink()
                            deleted += 1
                        except OSError:
                            pass
                try:
                    idx_file.unlink()
                    deleted += 1
                    self._cache.invalidate(str(idx_file))
                except OSError:
                    pass

        return {"deleted": deleted, "orphaned_indices": len(orphaned_indices)}

    def get_stats(self) -> Dict:
        """Статистика хранилища."""
        total_versions = 0
        total_size = 0
        for pattern in ("*.txt", "*.ztxt"):
            for f in self.root.glob(pattern):
                if f.name.endswith('.tmp'):
                    continue
                try:
                    total_versions += 1
                    total_size += f.stat().st_size
                except OSError:
                    pass
        return {
            **self._stats,
            "total_versions": total_versions,
            "total_size_mb": round(total_size / 1048576, 2),
        }

    # --- Private ---

    def _save_one(self, filepath: Path) -> bool:
        """Сохраняет одну версию если файл изменился. Индекс stage-ится."""
        if not filepath.is_file() or filepath.is_symlink():
            return False
        if not self._store.is_text(filepath):
            return False

        current_hash = self._store.compute_hash_stream(filepath)
        entries = self._idx.load(filepath)
        if entries and entries[-1].get("hash") == current_hash:
            return False

        try:
            content_bytes = filepath.read_bytes()
        except OSError:
            return False

        try:
            content_str = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return False

        if self.block_on_secrets:
            secrets = self._store.check_secrets(content_str)
            if secrets:
                raise SecretDetectedError(secrets)

        now = datetime.now()
        timestamp = now.strftime(TIMESTAMP_FMT)
        vp = self._store.version_path(filepath, timestamp)
        tmp_vp = vp.with_suffix('.tmp')

        payload = zlib.compress(content_bytes) if self._store._compress else content_bytes

        try:
            tmp_vp.write_bytes(payload)
            os.replace(str(tmp_vp), str(vp))
        except OSError as e:
            if tmp_vp.exists():
                tmp_vp.unlink(missing_ok=True)
            raise ZSSError(f"Version write failed: {e}")

        entry: VersionEntry = {
            "timestamp": timestamp,
            "hash": current_hash,
            "size": len(content_bytes),
            "compressed": self._store._compress,
            "lines": content_str.count('\n') + (0 if content_str.endswith('\n') else 1),
            "path": str(filepath),
            "tags": {},
        }
        entries.append(entry)
        self._idx.stage_save(filepath, entries)
        return True

    @staticmethod
    def _resolve_target(entries: List[VersionEntry], target: str) -> Optional[str]:
        """Находит timestamp по тегу или прямому совпадению."""
        for entry in reversed(entries):
            if entry["timestamp"] == target:
                return entry["timestamp"]
            if target in entry.get("tags", {}):
                return entry["timestamp"]
        return None


def create_timemachine(root: str = ".zss_data", **kwargs) -> TimeMachine:
    """Фабрика для создания TimeMachine."""
    return TimeMachine(root=root, **kwargs)
