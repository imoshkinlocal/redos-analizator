"""Isolated execution of the language workers.

Security properties of this layer (documented so they can be audited):

* every worker runs in its own process group and is killed with SIGKILL on
  wall-clock timeout (``os.killpg``);
* RLIMIT_CPU, RLIMIT_AS, RLIMIT_CORE and RLIMIT_FSIZE are applied before
  ``exec`` for native workers;
* PHP runs in Docker with ``--network none``, ``--read-only``, memory/CPU/PID
  limits when no native interpreter is available;
* the scanner never executes code from the scanned package -- only the pattern
  and the generated input string are passed to the engine.
"""

from __future__ import annotations

import json
import os
import platform
import select
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

WORKER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(WORKER_DIR))

# characters that are valid PCRE delimiters and rarely appear in patterns
_PHP_DELIMITERS = "\x01\x02~#%!@;:,\x03"


class WorkerError(Exception):
    pass


class WorkerTimeout(WorkerError):
    pass


class WorkerDead(WorkerError):
    pass


@dataclass
class Engine:
    language: str
    label: str
    command: List[str]
    version: str = "unknown"
    kind: str = "native"              # native | docker
    notes: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        return f"{self.label}@{self.version}"


_VERSION_CACHE: Dict[str, str] = {}


def _run_version(command: Sequence[str], timeout: float = 20.0) -> str:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout or proc.stderr or "").strip().splitlines()[0][:200]
    except Exception:
        return "unknown"


def detect_engine(language: str, config=None) -> Optional[Engine]:
    """Locate a usable engine for a language, or return None."""
    language = language.lower()
    if language == "python":
        version = platform.python_version()
        module = (config.get("dynamic.python_module")
                  or config.get("dynamic.engines.python")
                  or "re") if config is not None else "re"
        if module in ("auto", "", None):
            module = "re"
        command = [sys.executable, os.path.join(WORKER_DIR, "python_worker.py")]
        notes = []
        if module == "regex":
            notes.append("measuring the third-party 'regex' module, not stdlib re")
        return Engine(language="python",
                      label="python-regex" if module == "regex" else "python-re",
                      command=command, version=version, notes=notes,
                      env={"PYTHONPATH": PROJECT_ROOT,
                           "REDOS_PYTHON_MODULE": module})

    if language == "ruby":
        ruby = shutil.which("ruby")
        if not ruby:
            return None
        if ruby not in _VERSION_CACHE:
            _VERSION_CACHE[ruby] = _run_version([ruby, "-e", "print RUBY_VERSION"])
        return Engine(language="ruby", label="ruby-onigmo",
                      command=[ruby, os.path.join(WORKER_DIR, "ruby_worker.rb")],
                      version=_VERSION_CACHE[ruby])

    if language == "php":
        php = shutil.which("php")
        if php:
            if php not in _VERSION_CACHE:
                code = 'echo PHP_VERSION, "|", (defined("PCRE_VERSION") ? PCRE_VERSION : "unknown");'
                _VERSION_CACHE[php] = _run_version([php, "-r", code])
            return Engine(language="php", label="php-pcre2",
                          command=[php, os.path.join(WORKER_DIR, "php_worker.php")],
                          version=_VERSION_CACHE[php])
        if config is not None and config.get("dynamic.use_docker_for_php", True):
            docker = shutil.which("docker")
            if not docker:
                return None
            image = config.get("dynamic.php_docker_image", "php:8.2-cli")
            inspect = subprocess.run([docker, "image", "inspect", image],
                                     capture_output=True, text=True)
            if inspect.returncode != 0:
                return None
            key = f"docker:{image}"
            if key not in _VERSION_CACHE:
                _VERSION_CACHE[key] = _run_version(
                    [docker, "run", "--rm", "--network", "none", image, "php", "-r",
                     'echo PHP_VERSION, "|", (defined("PCRE_VERSION") ? PCRE_VERSION : "unknown");'],
                    timeout=60.0,
                )
            command = [
                docker, "run", "--rm", "-i",
                "--network", "none",
                "--read-only",
                "--security-opt", "no-new-privileges",
                "--memory", f"{int(config.limit('max_memory_mb') or 256)}m",
                "--cpus", "1",
                "--pids-limit", "64",
                "-v", f"{WORKER_DIR}:/redos:ro",
                image, "php", "/redos/php_worker.php",
            ]
            return Engine(language="php", label="php-pcre2-docker", command=command,
                          version=_VERSION_CACHE[key], kind="docker",
                          notes=[f"executed in Docker image {image} (network disabled, read-only FS)"])
        return None

    return None


def php_delimited(body: str, flags: str = "") -> str:
    """Turn a PCRE body into a delimited pattern, choosing a safe delimiter."""
    for delimiter in _PHP_DELIMITERS:
        if delimiter not in body:
            return f"{delimiter}{body}{delimiter}{flags}"
    return "/" + body.replace("/", "\\/") + "/" + flags


def _preexec(cpu_seconds: int, memory_bytes: int):
    def apply() -> None:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        except Exception:
            pass
    return apply


class WorkerSession:
    """One long-lived worker process, one JSON request at a time."""

    def __init__(self, engine: Engine, timeout: float, memory_mb: int = 256,
                 startup_timeout: float = 30.0):
        self.engine = engine
        self.timeout = timeout
        self.memory_mb = memory_mb
        self.startup_timeout = startup_timeout
        self.process: Optional[subprocess.Popen] = None
        self._buffer = b""
        self._stderr_path: Optional[str] = None

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self.process is not None:
            return
        env = dict(os.environ)
        env.update(self.engine.env)
        env.setdefault("PYTHONUNBUFFERED", "1")
        stderr = subprocess.DEVNULL
        cpu_seconds = max(1, int(self.timeout) + 2)
        preexec = _preexec(cpu_seconds, self.memory_mb * 1024 * 1024)
        self.process = subprocess.Popen(
            self.engine.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            env=env,
            bufsize=0,
            start_new_session=True,
            preexec_fn=None if self.engine.kind == "docker" else preexec,
        )
        self._buffer = b""

    def close(self) -> None:
        if self.process is None:
            return
        try:
            self.process.stdin.close()  # type: ignore[union-attr]
        except Exception:
            pass
        if self.process.poll() is None:
            self._kill()
        try:
            self.process.wait(timeout=5)
        except Exception:
            pass
        self.process = None

    def _kill(self) -> None:
        if self.process is None:
            return
        try:
            os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass

    def __enter__(self) -> "WorkerSession":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- protocol -----------------------------------------------------------
    def request(self, payload: dict, timeout: Optional[float] = None) -> dict:
        if self.process is None:
            self.start()
        assert self.process is not None and self.process.stdin is not None
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        try:
            self.process.stdin.write((json.dumps(payload) + "\n").encode())
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise WorkerDead(f"worker pipe closed: {exc}") from exc
        line = self._read_line(deadline)
        if line is None:
            self._kill()
            raise WorkerTimeout("wall-clock timeout")
        try:
            return json.loads(line)
        except ValueError as exc:
            raise WorkerDead(f"invalid worker response: {line[:200]!r}") from exc

    def _read_line(self, deadline: float) -> Optional[str]:
        assert self.process is not None and self.process.stdout is not None
        fd = self.process.stdout.fileno()
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                ready, _, _ = select.select([fd], [], [], remaining)
            except (OSError, ValueError):
                return None
            if not ready:
                return None
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return None
            if not chunk:
                raise WorkerDead("worker exited unexpectedly")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line.decode("utf-8", errors="replace")


class WorkerPool:
    """Detects engines once per scan and caches them."""

    def __init__(self, config):
        self.config = config
        self._engines: Dict[str, Optional[Engine]] = {}
        self._unavailable_notes: Dict[str, str] = {}

    def engine(self, language: str) -> Optional[Engine]:
        if language not in self._engines:
            self._engines[language] = detect_engine(language, self.config)
            if self._engines[language] is None:
                self._unavailable_notes[language] = self._explain(language)
        return self._engines[language]

    def unavailable_note(self, language: str) -> str:
        self.engine(language)
        return self._unavailable_notes.get(language, "engine unavailable")

    def _explain(self, language: str) -> str:
        if language == "php":
            return ("no php interpreter and no usable Docker image "
                    "(install php-cli or `docker pull php:8.2-cli`)")
        if language == "ruby":
            return "no ruby interpreter on PATH"
        return "no engine available"

    def session(self, language: str, timeout: float, memory_mb: int) -> Optional[WorkerSession]:
        engine = self.engine(language)
        if engine is None:
            return None
        startup = 30.0 if engine.kind == "docker" else max(10.0, timeout * 3)
        return WorkerSession(engine, timeout=timeout, memory_mb=memory_mb,
                             startup_timeout=startup)
