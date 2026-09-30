# relay_vless_new.py
# رله VLESS بهینه (بر اساس کد PXPANEL)
# سازگار با پنل kohxbbbb

import asyncio
import secrets
import socket
import time
from datetime import datetime, timezone

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    daily_traffic,
    connections,
    connections_lock,
    connection_sockets,
    link_ip_map,
    error_logs,
    logger,
    check_and_add_usage,
    count_connections_for_link,
    get_client_ip,
    save_db,
    _log_connection_event,
    _fmt_bytes,
    parse_expires_at,
    parse_trojan_header,
)

RELAY_BUF = 256 * 1024   # 256 KB


async def parse_vless_header(chunk: bytes):
    """پارسر هدر VLESS"""
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]


async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    """از WebSocket به TCP"""
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_add_usage(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            stats["total_requests"] += 1
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += len(data)
                    connections[conn_id]["last_seen"] = time.time()
            now = datetime.now(timezone.utc)
            hourly_traffic[now.strftime("%Y-%m-%d %H:00")] += len(data)
            daily_traffic[now.strftime("%Y-%m-%d")] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str, auth: str = "vless"):
    """از TCP به WebSocket"""
    first = True
    resp_prefix = b"\x00\x00" if auth == "vless" else b""
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_add_usage(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += len(data)
                    connections[conn_id]["last_seen"] = time.time()
            now = datetime.now(timezone.utc)
            hourly_traffic[now.strftime("%Y-%m-%d %H:00")] += len(data)
            daily_traffic[now.strftime("%Y-%m-%d")] += len(data)
            payload = (resp_prefix + data) if (first and resp_prefix) else data
            first = False
            await ws.send_bytes(payload)
    except Exception:
        pass


async def websocket_tunnel_v2(ws: WebSocket, uuid: str):
    """رله‌ی بهینه‌شده (بر اساس PXPANEL)"""
    await ws.accept()

    # auth رو از query بگیر
    auth = ws.query_params.get("auth", "vless")
    if auth not in ("vless", "trojan"):
        auth = "vless"

    # چک کاربر
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
        if link is None or not link.get("active"):
            await ws.close(code=1008, reason="not authorized")
            return
        link_copy = dict(link)
        max_conn = link.get("max_connections", 0)

    # چک انقضا
    expires_at = parse_expires_at(link_copy.get("expires_at"))
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        await ws.close(code=1008, reason="expired")
        return

    # چک max_connections
    if max_conn > 0:
        current = await count_connections_for_link(uuid)
        if current >= max_conn:
            await ws.close(code=1008, reason="max connections")
            return

    # IP
    ip = get_client_ip(ws)

    # ثبت اتصال
    conn_id = secrets.token_urlsafe(6)
    async with connections_lock:
        connections[conn_id] = {
            "uuid": uuid,
            "ip": ip,
            "transport": f"{auth}-ws",
            "connected_at": datetime.now(timezone.utc).isoformat(),
            "last_seen": time.time(),
            "bytes": 0,
        }
        connection_sockets[conn_id] = ws
        link_ip_map[uuid].add(ip)

    await _log_connection_event("connect", link_copy.get("label", uuid), uuid, ip)

    writer = None
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        # پارسر بر اساس auth
        if auth == "trojan":
            command, address, port, payload = await parse_trojan_header(first_chunk)
        else:
            command, address, port, payload = await parse_vless_header(first_chunk)

        if not await check_and_add_usage(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        async with connections_lock:
            if conn_id in connections:
                connections[conn_id]["bytes"] += len(first_chunk)

        logger.info(f"➡️  [{conn_id}] {auth} → {address}:{port}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port),
            timeout=10.0
        )
        # TCP_NODELAY
        try:
            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid, auth)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_db())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now(timezone.utc).isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now(timezone.utc).isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        info = None
        async with connections_lock:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info and info.get("uuid") and info.get("ip"):
                link_ip_map[info["uuid"]].discard(info["ip"])
        if info:
            try:
                connected_at = datetime.fromisoformat(info["connected_at"])
                duration_s = max(0, int((datetime.now(timezone.utc) - connected_at).total_seconds()))
            except Exception:
                duration_s = 0
            async with LINKS_LOCK:
                label = LINKS.get(info.get("uuid"), {}).get("label", info.get("uuid", uuid))
            extra = f"duration {duration_s}s, {_fmt_bytes(info.get('bytes', 0))}"
            await _log_connection_event("disconnect", label, info.get("uuid", uuid), info.get("ip", ip), extra)
