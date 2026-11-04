"""Synchronized HTTP test traffic without redirects or automatic retries.

Raw HTTP/1.1 is used only for the optional last-byte release mode. Every
request is first checked by the owning GuardedClient's read-only/path policy
and by the caller's host allowlist. Results contain status codes and timing
only; bodies and headers never leave this module.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from time import monotonic_ns
from urllib.parse import urlsplit

import httpx

from . import UnsafeRequest

_MODES = {"last_byte", "h2_single_packet", "burst"}
_H2_COALESCE_LIMIT = 1200


def _host_allowed(url: str, entries) -> bool:
    host = (urlsplit(url).hostname or "").rstrip(".").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True
    except ValueError:
        pass
    for entry in entries:
        candidate = str(entry).strip().rstrip(".").lower()
        if not candidate:
            continue
        if candidate == host:
            return True
        try:
            if urlsplit("//" + candidate).hostname == host:
                return True
        except ValueError:
            continue
    return False


def _prepare(client, request: dict) -> httpx.Request:
    if not isinstance(request, dict) or not isinstance(request.get("method"), str):
        raise ValueError("synchronized requests must be mappings with a method")
    method = request["method"]
    if "url" not in request:
        raise ValueError("synchronized requests require a url")
    if client._kill_file and __import__("os").path.exists(client._kill_file):
        raise UnsafeRequest("kill switch is active")
    headers = {**getattr(client, "_default_headers", {}), **dict(request.get("headers", {}))}
    kwargs = {"headers": headers}
    if "params" in request:
        kwargs["params"] = request["params"]
    if "json" in request:
        kwargs["json"] = request["json"]
    built = client._http.build_request(method, request["url"], **kwargs)
    path = built.url.raw_path.split(b"?", 1)[0].decode("ascii")
    if (client._read_only and built.method not in {"GET", "HEAD", "OPTIONS"}
            and (built.method, path) not in client._allowed):
        raise UnsafeRequest(f"read-only policy blocks {built.method} {path}")
    return built


def _wire(request: httpx.Request) -> bytes:
    body = request.content or b""
    lines = [f"{request.method} {request.url.raw_path.decode('ascii')} HTTP/1.1".encode("ascii")]
    has_host = False
    for name, value in request.headers.raw:
        lower = name.lower()
        if lower in (b"connection", b"transfer-encoding"):
            continue
        if lower == b"host":
            has_host = True
        lines.append(name + b": " + value)
    if not has_host:
        host = request.url.host
        port = request.url.port
        if port and not (request.url.scheme == "http" and port == 80) and not (
                request.url.scheme == "https" and port == 443):
            host = f"{host}:{port}"
        lines.append(b"Host: " + host.encode("ascii"))
    lines.extend((b"Connection: close", b"", body))
    return b"\r\n".join(lines)


def _status_line(data: bytes) -> int | None:
    first = data.split(b"\r\n", 1)[0]
    parts = first.split()
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    return int(parts[1])


async def _open(request: httpx.Request):
    url = request.url
    host = url.host
    port = url.port or (443 if url.scheme == "https" else 80)
    context = None
    server_hostname = None
    if url.scheme == "https":
        context = ssl.create_default_context()
        server_hostname = host
    reader, writer = await asyncio.open_connection(
        host, port, ssl=context, server_hostname=server_hostname,
    )
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    return reader, writer


async def _last_byte_round(client, requests: list[dict], allowed_hosts,
                           timeout: float) -> dict:
    prepared = []
    try:
        for item in requests:
            request = _prepare(client, item)
            if not _host_allowed(str(request.url), allowed_hosts):
                raise UnsafeRequest("host is not allowed for synchronized traffic")
            prepared.append((request, _wire(request)))
        await client._take_tokens(len(prepared))
    except Exception:
        raise

    pairs = []
    try:
        async def connect(request, wire):
            return (await _open(request)) + (wire,)
        connected = await asyncio.gather(*(connect(request, wire) for request, wire in prepared),
                                         return_exceptions=True)
        failures = [item for item in connected if isinstance(item, BaseException)]
        pairs = [item for item in connected if not isinstance(item, BaseException)]
        if failures:
            for _, writer, _ in pairs:
                writer.close()
            raise failures[0]
        for _, writer, _ in pairs:
            writer.write(b"")  # keep the writer visibly live before prefix writes
        for reader, writer, wire in pairs:
            if len(wire) < 2:
                raise ValueError("request wire is too short for last-byte synchronization")
            writer.write(wire[:-1])
        await asyncio.gather(*(writer.drain() for _, writer, _ in pairs))
        barrier = asyncio.Barrier(len(pairs))

        async def release(reader, writer, wire):
            await barrier.wait()
            stamp = monotonic_ns()
            writer.write(wire[-1:])
            return stamp, reader, writer

        released = await asyncio.gather(*(release(*pair) for pair in pairs))
        try:
            await asyncio.gather(*(writer.drain() for _, _, writer in released))
        except OSError:
            pass

        async def read_response(stamp, reader, writer):
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                return {"status": _status_line(line), "release_ns": stamp}
            except asyncio.TimeoutError:
                return {"error": "timeout", "release_ns": stamp}
            except Exception:
                return {"error": "execution_error", "release_ns": stamp}
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        records = await asyncio.gather(*(read_response(*item) for item in released))
        stamps = [record.pop("release_ns") for record in records]
        spread = (max(stamps) - min(stamps)) / 1_000_000
        return {"responses": records, "spread_ms": spread, "mode": "last_byte"}
    finally:
        for _, writer, _ in pairs:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _h2_round(client, requests: list[dict], allowed_hosts, timeout: float) -> dict:
    try:
        from h2.config import H2Configuration
        from h2.connection import H2Connection
    except ImportError:
        fallback = await _last_byte_round(client, requests, allowed_hosts, timeout)
        fallback["note"] = "h2_unavailable"
        return fallback

    prepared = []
    for item in requests:
        request = _prepare(client, item)
        if not _host_allowed(str(request.url), allowed_hosts):
            raise UnsafeRequest("host is not allowed for synchronized traffic")
        if request.url.scheme != "https":
            fallback = await _last_byte_round(client, requests, allowed_hosts, timeout)
            fallback["note"] = "h2_unavailable"
            return fallback
        prepared.append(request)
    await client._take_tokens(len(prepared))
    first = prepared[0]
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2"])
    reader = writer = None
    try:
        reader, writer = await asyncio.open_connection(
            first.url.host, first.url.port or 443, ssl=context,
            server_hostname=first.url.host,
        )
        tls = writer.get_extra_info("ssl_object")
        if tls is None or tls.selected_alpn_protocol() != "h2":
            fallback = await _last_byte_round(client, requests, allowed_hosts, timeout)
            fallback["note"] = "h2_unavailable"
            return fallback
        connection = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
        connection.initiate_connection()
        streams = []
        for position, request in enumerate(prepared):
            stream_id = connection.get_next_available_stream_id()
            headers = [
                (":method", request.method),
                (":scheme", request.url.scheme),
                (":authority", request.url.netloc.decode("ascii")),
                (":path", request.url.raw_path.decode("ascii")),
            ]
            for name, value in request.headers.items():
                lower = name.lower()
                if lower in {"host", "connection", "transfer-encoding", "content-length"}:
                    continue
                headers.append((lower, value))
            body = request.content or b""
            connection.send_headers(stream_id, headers, end_stream=False)
            if body:
                connection.send_data(stream_id, body, end_stream=False)
            streams.append((stream_id, position))
        writer.write(connection.data_to_send())
        await writer.drain()
        final_size = 0
        for stream_id, _ in streams:
            connection.send_data(stream_id, b"", end_stream=True)
            final_size += 9
        if final_size > _H2_COALESCE_LIMIT:
            fallback = await _last_byte_round(client, requests, allowed_hosts, timeout)
            fallback["note"] = "h2_coalesce_limit"
            return fallback
        stamp = monotonic_ns()
        writer.write(connection.data_to_send())
        await writer.drain()
        statuses = {}
        ended = set()
        deadline = asyncio.get_running_loop().time() + timeout
        while len(ended) < len(streams):
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            for event in connection.receive_data(data):
                if hasattr(event, "stream_id") and hasattr(event, "headers"):
                    if event.stream_id in {stream for stream, _ in streams}:
                        status = None
                        for name, value in event.headers:
                            if name == b":status" or name == ":status":
                                try:
                                    status = int(value)
                                except (TypeError, ValueError):
                                    status = None
                        if status is not None:
                            statuses[event.stream_id] = status
                if hasattr(event, "stream_id") and event.__class__.__name__ == "StreamEnded":
                    ended.add(event.stream_id)
            outbound = connection.data_to_send()
            if outbound:
                writer.write(outbound)
                await writer.drain()
        responses = []
        for stream_id, _ in streams:
            if stream_id in statuses:
                responses.append({"status": statuses[stream_id]})
            else:
                responses.append({"error": "timeout"})
        return {"responses": responses, "spread_ms": 0.0,
                "mode": "h2_single_packet", "release_ns": stamp}
    except Exception:
        fallback = await _last_byte_round(client, requests, allowed_hosts, timeout)
        fallback["note"] = "h2_unavailable"
        return fallback
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def _burst_round(client, requests: list[dict], timeout: float) -> dict:
    barrier = asyncio.Barrier(len(requests))

    async def send(item):
        await barrier.wait()
        stamp = monotonic_ns()
        request = _prepare(client, item)
        kwargs = {"headers": dict(request.headers), "follow_redirects": False, "auth": None}
        if "params" in item:
            kwargs["params"] = item["params"]
        if "json" in item:
            kwargs["json"] = item["json"]
        try:
            response = await client.request(request.method, request.url, **kwargs)
            return {"status": response.status_code, "release_ns": stamp}
        except asyncio.TimeoutError:
            return {"error": "timeout", "release_ns": stamp}
        except Exception:
            return {"error": "execution_error", "release_ns": stamp}

    records = await asyncio.gather(*(send(item) for item in requests))
    stamps = [record.pop("release_ns") for record in records]
    return {"responses": records, "spread_ms": (max(stamps) - min(stamps)) / 1_000_000,
            "mode": "burst"}


async def send_synchronized(client, requests, *, mode="last_byte", max_spread_ms=5.0,
                            inter_round_delay=0.05, allowed_hosts=()) -> dict:
    if mode not in _MODES:
        raise ValueError("sync mode must be last_byte, h2_single_packet or burst")
    if not isinstance(requests, list) or not requests:
        raise ValueError("synchronized requests must be a nonempty list")
    if max_spread_ms <= 0:
        raise ValueError("max_spread_ms must be positive")
    timeout = client._http.timeout.read or 15.0
    if timeout is None or timeout <= 0:
        timeout = 15.0
    if mode == "burst":
        result = await _burst_round(client, requests, timeout)
    elif mode == "h2_single_packet":
        result = await _h2_round(client, requests, tuple(allowed_hosts), timeout)
    else:
        result = await _last_byte_round(client, requests, tuple(allowed_hosts), timeout)
    await asyncio.sleep(max(0.0, float(inter_round_delay)))
    return result
