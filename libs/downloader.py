#!/usr/bin/env python3

from queue import Queue
import urllib.error
import urllib.request
import threading
from typing import Optional

class ProxyDownloader:
    _sources: set[str]
    _proxies: set[str]
    _lock: threading.Lock
    _queue: Queue[str]

    def __init__(self):
        self._sources = set()
        self._proxies = set()

        self._lock = threading.Lock()
        self._queue = Queue()


    def add(self, source: str) -> bool:
        with self._lock:
            if source in self._sources:
                return False
            self._sources.add(source)
        return True 

    def remove(self, source: str) -> bool:
        with self._lock:
            if source not in self._sources:
                return False
            self._sources.discard(source)
        return True

    def get_sources(self) -> list[str]:
        with self._lock:
            return sorted(self._sources)

    def get_responses(self) -> list[str]:
        with self._lock:
            return sorted(self._proxies)

    def run(
        self,
        thread_count: int = 10,
        timeout: Optional[float] = None,
        daemon: bool = True,
    ) -> list[threading.Thread]:
        if timeout is None:
            timeout = 5.0

        with self._lock:
            for s in self._sources:
                self._queue.put(s)

            workers: list[threading.Thread] = []
            for _ in range(max(1, int(thread_count))):
                t = threading.Thread(
                    target=self._worker,
                    daemon=daemon
                )
                t.start()
                workers.append(t)
            return workers

    def _worker(self) -> None:
        while True:
            try:
                source: str = self._queue.get_nowait()
                resp: str = ""
            except Exception:
                break
            try:
                http_request = urllib.request.Request(
                    source,
                    data=None,
                    method="GET",
                )
                with urllib.request.urlopen(http_request) as http_response:
                        resp = http_response.read().decode()
            except urllib.error.HTTPError as e:
                print(f"ERROR: {e.msg}")
                break
            except Exception:
                break
            finally:
                self._finalize(source, resp)
                self._queue.task_done()

    def _finalize(self, source: str, resp: str) -> None:
        with self._lock:
            self._sources.discard(source)
            for p in resp.split("\r\n"):
                if p != "":
                    self._proxies.add(p)

