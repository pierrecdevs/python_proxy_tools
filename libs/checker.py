#!/usr/bin/env python3
import threading
import socket
import ssl
import time
import base64
from urllib.parse import urlparse, ParseResult
from queue import Queue


class ProxyChecker:
    _pending: set[str]
    _valid: set[str]
    _invalid: set[str]
    _lock: threading.Lock
    _queue: Queue[str]
    _creds: dict[str, tuple[str, str]]
    default_timeout: float

    def __init__(self, default_timeout: float = 5.0) -> None:
        self._pending = set()
        self._valid = set()
        self._invalid = set()

        self._lock = threading.Lock()
        self._queue = Queue()

        self._creds: dict[str, tuple[str, str]] = {}

        self.default_timeout = default_timeout

    def add(self, proxy: str) -> bool:
        parsed: ParseResult | None = self._parse_proxy(proxy)
        if parsed is None:
            return False

        normalized = self._normalize_proxy(parsed)

        with self._lock:
            if normalized in self._valid or \
                    normalized in self._invalid or \
                    normalized in self._pending:
                return False
            self._pending.add(normalized)
            if parsed.username and parsed.password:
                self._creds[normalized] = (parsed.username, parsed.password)
        return True

    def remove(self, proxy: str) -> bool:
        parsed: ParseResult | None = self._parse_proxy(proxy)
        if parsed is None:
            return False

        normalized = self._normalize_proxy(parsed)
        removed: bool = False

        with self._lock:
            removed |= normalized in self._valid and \
                not self._valid.discard(
                    normalized)
            removed |= normalized in self._invalid and \
                not self._invalid.discard(
                    normalized)
            removed |= normalized in self._pending and \
                not self._pending.discard(
                    normalized)
            self._creds.pop(normalized, None)
        return removed

    def all(self) -> list[str]:
        with self._lock:
            return sorted(self._valid | self._invalid | self._pending)

    def get_valid(self) -> list[str]:
        with self._lock:
            return sorted(self._valid)

    def get_invalid(self) -> list[str]:
        with self._lock:
            return sorted(self._invalid)

    def get_pending(self) -> list[str]:
        with self._lock:
            return sorted(self._pending)

    def run(self,
            thread_count: int = 10,
            timeout: float | None = None,
            test_host: str = "example.com",
            test_port: int = 80,
            test_use_tls: bool = False,
            http_path: str = "/",
            daemon: bool = True
            ) -> list[threading.Thread]:
        if timeout is None:
            timeout = self.default_timeout

        with self._lock:
            for p in self._pending:
                self._queue.put(p)

        workers: list[threading.Thread] = []
        for _ in range(max(1, int(thread_count))):
            t = threading.Thread(
                target=self._worker,
                args=(timeout, test_host, test_port, test_use_tls, http_path),
                daemon=daemon
            )
            t.start()
            workers.append(t)
        return workers

    def _worker(
            self,
            timeout: float,
            test_host: str,
            test_port: int,
            test_use_tls: bool,
            http_path: str,
    ) -> None:
        while True:
            try:
                proxy: str = self._queue.get_nowait()
            except Exception:
                break

            scheme, host, port = self._split_proxy(proxy)
            creds: tuple[str, str] | None = self._creds.get(proxy)
            ok: bool = False
            try:
                if scheme == "http":
                    ok = self._check_http_proxy(
                        host,
                        port,
                        timeout,
                        test_host,
                        test_port,
                        http_path,
                        use_tls=test_use_tls,
                        creds=creds,
                    )
                elif scheme == "https":
                    ok = self._check_http_connect_tls_proxy(
                        host,
                        port,
                        timeout,
                        test_host,
                        test_port,
                        http_path,
                        test_use_tls=True,
                        creds=creds
                    )
                elif scheme == "socks5":
                    ok = self._check_socks5_proxy(
                        host,
                        port,
                        timeout,
                        test_host,
                        test_port,
                        use_tls=True,
                        creds=creds
                    )
            except Exception:
                ok = False
            finally:
                self._finalize(proxy, ok)
                self._queue.task_done()

    def _finalize(self, proxy: str, ok: bool) -> None:
        with self._lock:
            self._pending.discard(proxy)
            if ok:
                self._invalid.discard(proxy)
                self._valid.add(proxy)
            else:
                self._valid.discard(proxy)
                self._invalid.add(proxy)

    # -----------------------
    # Parsing / Normalization
    # -----------------------
    @staticmethod
    def _parse_proxy(proxy: str) -> ParseResult | None:
        try:
            parsed = urlparse(proxy.strip())
            if not parsed.scheme or not parsed.hostname or not parsed.port:
                return None
            return parsed
        except Exception:
            return None

    @staticmethod
    def _split_proxy(proxy: str) -> tuple[str, str, int]:
        parsed: ParseResult = urlparse(proxy)
        scheme: str = parsed.scheme.lower() if parsed.scheme is not None else ""
        host: str = parsed.hostname.lower() if parsed.hostname is not None else ""
        port: int = int(parsed.port or 0)
        return scheme, host, port

    @staticmethod
    def _normalize_proxy(parsed: ParseResult) -> str:
        scheme: str = parsed.scheme.lower() if parsed.scheme is not None else ""
        host: str = parsed.hostname.lower() if parsed.hostname else ""
        port: int = int(parsed.port or 0)

        return f"{scheme}://{host}:{port}"

    def _check_http_proxy(
        self,
        proxy_host: str,
        proxy_port: int,
        timeout: float,
        dest_host: str,
        dest_port: int,
        http_path: str,
        use_tls: bool,
        creds: tuple[str, str] | None,
    ) -> bool:
        try:
            if dest_port == 80 and not use_tls:
                auth_header = ""
                if creds:
                    user, pw = creds
                    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
                    auth_header = f"Proxy-Authorization: Basic {token}\r\n"
                request: str = (
                    f"GET http://{dest_host}{http_path} HTTP/1.1\r\n"
                    f"Host: {dest_host}\r\n"
                    f"{auth_header}"
                    "Connection: Close\r\n"
                    "User-Agent: ProxyCheck/1.0\r\n"
                    "\r\n"
                )
                return self._http_send_and_recv(
                    proxy_host,
                    proxy_port,
                    timeout,
                    request,
                    expect_status=True,
                )
            else:
                return self._check_http_connect_tls_proxy(
                    proxy_host,
                    proxy_port,
                    timeout,
                    dest_host,
                    dest_port,
                    http_path,
                    test_use_tls=use_tls,
                    creds=creds,
                )
        except:
            return False

    def _check_http_connect_tls_proxy(
        self,
        proxy_host: str,
        proxy_port: int,
        timeout: float,
        dest_host: str,
        dest_port: int,
        http_path: str,
        test_use_tls: bool,
        creds: tuple[str, str] | None
    ) -> bool:

        s: socket.socket | None = None
        try:
            s = socket.create_connection(
                (proxy_host, proxy_port), timeout=timeout)
            s.settimeout(timeout)

            auth_header = ""
            if creds:
                user, pw = creds
                token = base64.b64encode(f"{user}:{pw}".encode()).decode()
                auth_header = f"Proxy-Authorization: Basic {token}\r\n"

            connect_req: str = (
                f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
                f"Host: {dest_host}:{dest_port} HTTP/1.1\r\n"
                f"{auth_header}"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: ProxyCheck/1.0\r\n"
                "\r\n"
            )
            s.sendall(connect_req.encode("ascii"))
            resp: bytes | None = self._recv_until(s, b"\r\n\r\n", timeout)

            if not resp:
                return False

            status_line: bytes = resp.split(b"\r\n", 1)[0]
            if b"200" not in status_line or b"301" not in status_line:
                return False

            if test_use_tls:
                ctx: ssl.SSLContext = ssl.create_default_context()
                tls: ssl.SSLSocket = ctx.wrap_socket(
                    s, server_hostname=dest_host)
                req: str = (
                    f"HEAD {http_path} HTTP/1.1\r\n"
                    f"Host {dest_host}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: ProxyChecker/1.0\r\n"
                    "\r\n"
                )
                tls.sendall(req.encode("ascii"))
                data: bytes | None = self._recv_some(tls, timeout)
                return bool(data and b"HTTP/" in data)
            else:
                req: str = (
                    f"HEAD {http_path} HTTP/1.1\r\n"
                    f"Host {dest_host}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: ProxyChecker/1.0\r\n"
                    "\r\n"
                )
                s.sendall(req.encode("ascii"))
                data: bytes | None = self._recv_some(s, timeout)
                return bool(data and b"HTTP/" in data)

        except Exception:
            return False

        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

    def _check_socks5_proxy(
        self,
        proxy_host: str,
        proxy_port: int,
        timeout: float,
        dest_host: str,
        dest_port: int,
        use_tls: bool,
        creds: tuple[str, str] | None,
    ) -> bool:
        s: socket.socket | None = None
        try:
            s = socket.create_connection(
                (proxy_host, proxy_port), timeout=timeout)
            s.settimeout(timeout)

            if creds:
                s.sendall(b"\x05\x01\x02")
                resp = self._recv_exact(s, 2, timeout)
                if not resp or resp[1] != 0x02:
                    return False

                user, pw = creds
                u_bytes, p_bytes = user.encode(), pw.encode()
                req = bytearray([0x01, len(u_bytes)]) + \
                    u_bytes + bytearray([len(p_bytes)]) + p_bytes
                s.sendall(req)
                auth_resp = self._recv_exact(s, 2, timeout)
                if not auth_resp or auth_resp[1] != 0x00:
                    return False
            else:
                # Packet: Greeting version 5, 1 method, no-auth (0x00)
                s.sendall(b"\x05\x01\x00")
                resp: bytes | None = self._recv_exact(s, 2, timeout)
                if not resp or resp[0] != 0x05 or resp[1] != 0x00:
                    return False

            # CONNECT request:
            # VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (domain),DST.ADDR, DST.PORT
            host_bytes: bytes = dest_host.encode("idna")
            req: bytearray = bytearray(
                [0x05, 0x01, 0x00, 0x03, len(host_bytes)])
            req.extend(host_bytes)
            req.extend(dest_port.to_bytes(2, byteorder="big"))
            s.sendall(req)

            # SERVER reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            header: bytes | None = self._recv_exact(s, 4, timeout)
            if not header or header[0] != 0x05 or header[1] != 0x00:
                return False

            atyp: int = header[3]
            if atyp == 0x01:  # IPv4
                addr = self._recv_exact(s, 4, timeout)
            elif atyp == 0x03:  # Domain
                ln = self._recv_exact(s, 1, timeout)
                if not ln:
                    return False
                addr = self._recv_exact(s, ln[0], timeout)
            elif atyp == 0x04:  # IPv6
                addr = self._recv_exact(s, 16, timeout)
            else:
                return False

            if not addr:
                return False

            if not self._recv_exact(s, 2, timeout):
                return False

            if use_tls:
                ctx: ssl.SSLContext = ssl.create_default_context()
                tls: ssl.SSLSocket = ctx.wrap_socket(
                    s, server_hostname=dest_host)
                req_str: str = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host {dest_host}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: ProxyChecker/1.0\r\n"
                    "\r\n"
                )
                tls.sendall(req_str.encode("ascii"))
                data: bytes | None = self._recv_some(tls, timeout)
                return bool(data and b"HTTP/" in data)
            else:
                req_str: str = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host {dest_host}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: ProxyChecker/1.0\r\n"
                    "\r\n"
                )
                s.sendall(req_str.encode("ascii"))
                data: bytes | None = self._recv_some(s, timeout)
                return bool(data and b"HTTP/" in data)
        except:
            return False
        finally:
            if s is not None:
                try:
                    s.close()
                except:
                    pass

    def _http_send_and_recv(
        self,
        host: str,
        port: int,
        timeout: float,
        request: str,
        expect_status: bool
    ) -> bool:
        s: socket.socket | None = None
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(request.encode("ascii"))

            data: bytes | None = self._recv_some(s, timeout)
            if not data:
                return False
            if expect_status:
                return data.startswith(b"HTTP/1.") or data.startswith(b"HTTP/2")
            return True
        except:
            return False
        finally:
            if s is not None:
                try:
                    s.close()
                except:
                    pass

    @staticmethod
    def _recv_some(sock: socket.socket, timeout: float, max_bytes: int = 4096) -> bytes | None:
        try:
            sock.settimeout(timeout)
            return sock.recv(max_bytes)
        except Exception:
            return None

    @staticmethod
    def _recv_until(sock: socket.socket, marker: bytes, timeout: float, max_bytes=65536) -> bytes | None:
        buf: bytearray = bytearray()
        start: float = time.time()
        try:
            sock.settimeout(timeout)
            while time.time() - start < timeout and len(buf) < max_bytes:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buf.extend(chunk)
                if marker in buf:
                    return bytes(buf)
            return bytes(buf) if buf else None
        except Exception:
            return None

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes | None:
        buf: bytearray = bytearray()
        start: float = time.time()

        try:
            sock.settimeout(timeout)
            while len(buf) < n and time.time() - start < timeout:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    break
                buf.extend(chunk)
            return bytes(buf) if len(buf) == n else None
        except Exception:
            return None
