import os, json, difflib, fcntl, re, time, logging, hashlib, zlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from contextlib import contextmanager
import threading

logger = logging.getLogger("zss")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

TIMESTAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_\d{6}$')
INDEX_VERSION = 3
SECRET_RE = re.compile(r'(?i)(?:api_key|token|password|secret)\s*[:=]\s*["\'][^"\']{8,}["\']')

class ZSSError(Exception): pass
class CorruptedIndexError(ZSSError): pass
class SecretDetectedError(ZSSError): pass

class LRUCache:
    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.cache: Dict[str, Tuple] = {}
        self.lock = threading.Lock()

    def get_valid(self, key: str, current_mtime: float, ttl: float) -> Optional[List[Dict]]:
        with self.lock:
            if key in self.cache:
                index, cached_mtime, cached_time = self.cache[key]
                if (time.time() - cached_time) < ttl and current_mtime == cached_mtime:
                    return index
        return None

    def put(self, key: str, index: List[Dict], current_mtime: float):
        with self.lock:
            if len(self.cache) >= self.max_size:
                self.cache.pop(next(iter(self.cache)), None)
            self.cache[key] = (index, current_mtime, time.time())

    def invalidate(self, key: str):
        with self.lock:
            self.cache.pop(key, None)

class FileLock:
    def __init__(self, lock_file: Path):
        self.lock_file = lock_file
        self._fd = None

    @contextmanager
    def exclusive(self):
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self._fd = open(self.lock_file, 'w')
        try:
            fcntl.flock(self._fd.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(self._fd.fileno(), fcntl.LOCK_UN)
            self._fd.close()
            self._fd = None

class IndexManager:
    def __init__(self, root: Path, cache: LRUCache, ttl: float):
        self.root = root
        self.cache = cache
        self.ttl = ttl

    def _get_index_path(self, filepath: Path) -> Path:
        return self.root / f"{hashlib.md5(str(filepath.resolve()).encode()).hexdigest()[:24]}.index.json"

    def load(self, filepath: Path) -> List[Dict]:
        index_file = self._get_index_path(filepath)
        cache_key = str(index_file)
        try:
            current_mtime = index_file.stat().st_mtime
        except OSError:
            current_mtime = 0

        cached = self.cache.get_valid(cache_key, current_mtime, self.ttl)
        if cached is not None:
            return cached

        try:
            if not index_file.exists():
                index, current_mtime = [], 0
            else:
                current_mtime = index_file.stat().st_mtime
                data = json.loads(index_file.read_text())
                if isinstance(data, dict) and data.get("version") == INDEX_VERSION:
                    index = data.get("entries", [])
                elif isinstance(data, list):
                    index = data
                else:
                    raise CorruptedIndexError("Unknown format")
        except (json.JSONDecodeError, CorruptedIndexError, KeyError):
            logger.warning(f"Corrupted index for {filepath}")
            index, current_mtime = [], 0
        except IOError as e:
            logger.error(f"Cannot read index for {filepath}: {e}")
            index, current_mtime = [], 0

        self.cache.put(cache_key, index, current_mtime)
        return index

    def save(self, filepath: Path, index: List[Dict]):
        index_file = self._get_index_path(filepath)
        tmp = index_file.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps({"version": INDEX_VERSION, "entries": index}, indent=2))
            os.replace(str(tmp), str(index_file))
        except IOError as e:
            if tmp.exists(): tmp.unlink(missing_ok=True)
            raise ZSSError(f"Failed to save index: {e}")
        self.cache.invalidate(str(index_file))

class VersionStore:
    def __init__(self, root: Path, index_mgr: IndexManager, compress: bool):
        self.root = root
        self.index_mgr = index_mgr
        self.compress = compress

    def _get_version_path(self, filepath: Path, timestamp: str) -> Path:
        if not TIMESTAMP_RE.match(timestamp):
            raise ZSSError(f"Invalid timestamp: {timestamp}")
        safe = hashlib.md5(str(filepath.resolve()).encode()).hexdigest()[:24]
        ext = ".ztxt" if self.compress else ".txt"
        return self.root / f"{safe}.{timestamp}{ext}"

    @staticmethod
    def compute_hash(content: bytes) -> str:
        return hashlib.blake2b(content, digest_size=8).hexdigest()

    @staticmethod
    def is_text_file(content_bytes: bytes) -> bool:
        if not content_bytes: return True
        sample = content_bytes[:8192]
        if b'\x00' in sample:
            return sample.startswith(b'\xff\xfe') or sample.startswith(b'\xfe\xff')
        return True

    @staticmethod
    def check_secrets(content: str) -> List[str]:
        return SECRET_RE.findall(content)

    def save_version(self, filepath: Path, block_on_secrets: bool = False) -> bool:
        filepath = filepath.resolve()
        if not filepath.is_file() or filepath.is_symlink(): return False
        try:
            content_bytes = filepath.read_bytes()
        except (IOError, PermissionError):
            return False

        if not self.is_text_file(content_bytes): return False
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return False

        if block_on_secrets and self.check_secrets(content):
            raise SecretDetectedError("Potential secrets detected in file")

        file_hash = self.compute_hash(content_bytes)
        index = self.index_mgr.load(filepath)
        if index and index[-1].get("hash") == file_hash:
            return False

        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d_%H-%M-%S") + f"_{now.microsecond:06d}"
        version_file = self._get_version_path(filepath, timestamp)
        tmp_version = version_file.with_suffix(".tmp")

        payload = zlib.compress(content_bytes) if self.compress else content_bytes

        try:
            tmp_version.write_bytes(payload)
            os.replace(str(tmp_version), str(version_file))
            index.append({
                "timestamp": timestamp, "hash": file_hash,
                "size": len(content_bytes), "compressed": self.compress,
                "lines": len(content.splitlines()), "path": str(filepath),
                "tags": {}
            })
            self.index_mgr.save(filepath, index)
            logger.info(f"Saved: {filepath.name} ({timestamp})")
            return True
        except (IOError, PermissionError) as e:
            if tmp_version.exists(): tmp_version.unlink(missing_ok=True)
            raise ZSSError(f"Failed to save version: {e}")

    def get_version_bytes(self, filepath: Path, timestamp: str) -> Optional[bytes]:
        version_file = self._get_version_path(filepath, timestamp)
        if not version_file.exists():
            fallback = self._get_version_path(filepath, timestamp).with_suffix(".txt")
            if fallback.exists(): version_file = fallback
            
        if not version_file.exists():
            return None
            
        payload = version_file.read_bytes()
        return zlib.decompress(payload) if version_file.suffix == ".ztxt" else payload

class TimeMachine:
    def __init__(self, root: str = ".timemachine", extensions: Optional[List[str]] = None,
                 keep_default: int = 100, cache_ttl: float = 1.0, max_cache_size: int = 100,
                 compress: bool = True, block_on_secrets: bool = False):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.extensions = extensions or [".py"]
        self.keep_default = keep_default
        self.block_on_secrets = block_on_secrets
        
        self._cache = LRUCache(max_cache_size)
        self._lock = FileLock(self.root / ".lock")
        self._index_mgr = IndexManager(self.root, self._cache, cache_ttl)
        self._store = VersionStore(self.root, self._index_mgr, compress)
        
        self.stats = {"tracked": 0, "saved": 0, "rollbacks": 0, "errors": 0}

    def track(self, paths: Optional[List[str]] = None) -> Dict:
        files = []
        if paths:
            for p in paths:
                path = Path(p).resolve()
                if path.is_file() and not path.is_symlink() and path.suffix in self.extensions:
                    files.append(path)
        else:
            for ext in self.extensions:
                for file in Path(".").rglob(f"*{ext}"):
                    if ".timemachine" not in str(file) and not file.name.startswith("."):
                        files.append(file)

        saved_count = 0
        total_checked = len(files)
        
        with self._lock.exclusive():
            for filepath in files:
                try:
                    if self._store.save_version(filepath, self.block_on_secrets):
                        saved_count += 1
                except SecretDetectedError as e:
                    logger.error(f"BLOCKED {filepath}: {e}")
                    self.stats["errors"] += 1
                except KeyboardInterrupt:
                    logger.info(f"Interrupted at {filepath}")
                    break
                except ZSSError as e:
                    logger.warning(f"Skip {filepath}: {e}")
                    self.stats["errors"] += 1

        self.stats["tracked"] += total_checked
        self.stats["saved"] += saved_count
        
        if saved_count > 0:
            logger.info(f"Tracked: {saved_count} saved, {total_checked - saved_count} unchanged")
        return {"checked": total_checked, "saved": saved_count, "errors": self.stats["errors"]}

    def history(self, filename: str, limit: int = 10) -> List[Dict]:
        return self._index_mgr.load(Path(filename).resolve())[-limit:]

    def add_tag(self, filename: str, timestamp: str, tag: str):
        filepath = Path(filename).resolve()
        index = self._index_mgr.load(filepath)
        for entry in index:
            if entry["timestamp"] == timestamp:
                entry.setdefault("tags", {})[tag] = timestamp
                self._index_mgr.save(filepath, index)
                logger.info(f"Tag '{tag}' added to {timestamp}")
                return
        raise ZSSError("Timestamp not found in history")

    def rollback(self, filename: str, target: str) -> str:
        filepath = Path(filename).resolve()
        index = self._index_mgr.load(filepath)
        
        timestamp = target
        for entry in index:
            if entry.get("tags", {}).get(target) == target or entry["timestamp"] == target:
                timestamp = entry["timestamp"]
                break
        else:
            return f"Version or tag {target} not found"

        content = self._store.get_version_bytes(filepath, timestamp)
        if content is None:
            return f"Version data for {timestamp} not found"
        
        with self._lock.exclusive():
            tmp_file = filepath.with_suffix(".tmp.rollback")
            try:
                tmp_file.write_bytes(content)
                os.replace(str(tmp_file), str(filepath))
                self.stats["rollbacks"] += 1
                return f"Rolled back {filename} to {timestamp}"
            except (IOError, PermissionError) as e:
                if tmp_file.exists(): tmp_file.unlink(missing_ok=True)
                return f"Rollback failed: {e}"

    def diff(self, filename: str, ts1: str, ts2: str) -> List[str]:
        filepath = Path(filename).resolve()
        f1 = self._store._get_version_path(filepath, ts1)
        f2 = self._store._get_version_path(filepath, ts2)
        
        if not f1.exists(): f1 = f1.with_suffix(".txt")
        if not f2.exists(): f2 = f2.with_suffix(".txt")

        if not f1.exists() or not f2.exists():
            return ["One or both versions not found"]

        def read_lines(fpath: Path):
            try:
                payload = fpath.read_bytes()
                text = zlib.decompress(payload).decode("utf-8") if fpath.suffix == ".ztxt" else payload.decode("utf-8")
                yield from text.splitlines(keepends=True)
            except UnicodeDecodeError:
                payload = fpath.read_bytes()
                text = zlib.decompress(payload).decode("latin-1") if fpath.suffix == ".ztxt" else payload.decode("latin-1")
                yield from text.splitlines(keepends=True)

        return list(difflib.unified_diff(
            read_lines(f1), read_lines(f2),
            fromfile=f"{filename}@{ts1}", tofile=f"{filename}@{ts2}"
        ))

    def clean(self, filename: str, keep: Optional[int] = None, max_age_minutes: int = 60) -> Dict:
        keep = keep or self.keep_default
        filepath = Path(filename).resolve()
        index = self._index_mgr.load(filepath)
        
        if len(index) <= keep:
            return {"deleted": 0, "kept": len(index)}

        to_delete = index[:-keep]
        deleted = 0
        
        with self._lock.exclusive():
            for entry in to_delete:
                try:
                    v_file = self._store._get_version_path(filepath, entry['timestamp'])
                    if v_file.exists(): v_file.unlink()
                    else:
                        v_file_txt = v_file.with_suffix(".txt")
                        if v_file_txt.exists(): v_file_txt.unlink()
                    deleted += 1
                except (ZSSError, IOError):
                    continue
            self._index_mgr.save(filepath, index[-keep:])

        now = time.time()
        tmp_cleaned = 0
        for tmp in self.root.glob("*.tmp"):
            try:
                if now - tmp.stat().st_mtime > max_age_minutes * 60:
                    tmp.unlink()
                    tmp_cleaned += 1
            except (IOError, OSError):
                continue

        return {"versions_deleted": deleted, "tmp_cleaned": tmp_cleaned, "kept": keep}

    def purge_missing(self, known_files: Optional[List[str]] = None) -> Dict:
        if known_files is None:
            known_files = [str(p.resolve()) for ext in self.extensions for p in Path(".").rglob(f"*{ext}") 
                           if ".timemachine" not in str(p) and not p.name.startswith(".")]
        known_set = set(known_files)
        orphaned = []
        
        for index_file in self.root.glob("*.index.json"):
            if index_file.name == ".lock.index.json": continue
            try:
                data = json.loads(index_file.read_text())
                entries = data.get("entries", []) if isinstance(data, dict) else data
                if not entries: continue
                if not {e.get("path") for e in entries if e.get("path")}.intersection(known_set):
                    orphaned.append(index_file)
            except (json.JSONDecodeError, IOError):
                continue

        deleted = 0
        with self._lock.exclusive():
            for idx_file in orphaned:
                try:
                    prefix = idx_file.stem
                    for v_file in self.root.glob(f"{prefix}.*"):
                        if v_file.suffix in [".txt", ".ztxt"]:
                            v_file.unlink()
                            deleted += 1
                    idx_file.unlink()
                    deleted += 1
                    self._cache.invalidate(str(idx_file))
                except (IOError, OSError):
                    continue
        return {"deleted": deleted, "orphaned_files": len(orphaned)}

    def get_stats(self) -> Dict:
        total_versions = 0
        total_size = 0
        for f in self.root.glob("*.txt"):
            if not f.name.endswith(".tmp"):
                try:
                    total_versions += 1
                    total_size += f.stat().st_size
                except (OSError, PermissionError):
                    continue
        for f in self.root.glob("*.ztxt"):
            if not f.name.endswith(".tmp"):
                try:
                    total_versions += 1
                    total_size += f.stat().st_size
                except (OSError, PermissionError):
                    continue
        return {**self.stats, "total_versions": total_versions, "total_size_mb": round(total_size / 1048576, 2)}

def create_timemachine(root: str = ".timemachine", **kwargs) -> TimeMachine:
    return TimeMachine(root, **kwargs)