#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import signal
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
from aiohttp import web

# Environment Variables
UUID = os.environ.get('UUID', 'e2f9d45a-8b3c-4d1e-9a2f-6b7c8d9e0f1a')
DOMAIN = os.environ.get('DOMAIN', '')
SUB_PATH = os.environ.get('SUB_PATH', 'sub')
NAME = os.environ.get('NAME', '')
WSPATH = os.environ.get('WSPATH', UUID[:8])
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

# Global Variables
CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''
http_session: aiohttp.ClientSession = None

# DNS Servers & Blocked Domains
DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
    'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
]

# Logging Configuration
log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Suppress heavy logs
for logger_name in ['aiohttp.access', 'aiohttp.server', 'aiohttp.client', 'aiohttp.internal', 'aiohttp.websocket']:
    logging.getLogger(logger_name).setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

def is_blocked_domain(host: str) -> bool:
    if not host:
        return False
    host_lower = host.lower()
    return any(host_lower == blocked or host_lower.endswith('.' + blocked) 
              for blocked in BLOCKED_DOMAINS)

async def get_isp():
    global ISP, http_session
    if ISP:
        return
    try:
        if http_session and not http_session.closed:
            async with http_session.get('https://api.ip.sb/geoip', 
                                         headers={'User-Agent': 'Mozilla/5.0'},
                                         timeout=aiohttp.ClientTimeout(total=3)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ISP = f"{data.get('country_code', '')}-{data.get('isp', '')}".replace(' ', '_')
                    return
    except Exception:
        pass
    ISP = 'Unknown'

async def get_ip():
    global CurrentDomain, Tls, CurrentPort, http_session
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            if http_session and not http_session.closed:
                async with http_session.get('https://api-ipv4.ip.sb/ip', timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        ip = await resp.text()
                        CurrentDomain = ip.strip()
                        Tls = 'none'
                        CurrentPort = PORT
        except Exception as e:
            if DEBUG:
                logger.error(f'Failed to get IP: {e}')
            CurrentDomain = 'change-your-domain.com'
            Tls = 'tls'
            CurrentPort = 443
    else:
        CurrentDomain = DOMAIN
        Tls = 'tls'
        CurrentPort = 443

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    
    global http_session
    if http_session and not http_session.closed:
        for dns_server in DNS_SERVERS:
            try:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with http_session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
            except Exception:
                continue
    
    return host

class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid_bytes = bytes.fromhex(uuid)
        
    async def handle_vless(self, websocket: web.WebSocketResponse, first_msg: bytes) -> bool:
        """Handle VLESS Protocol with Safe Task Management"""
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            
            if first_msg[1:17] != self.uuid_bytes:
                return False
            
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            
            host = ''
            if atyp == 1:
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode('utf-8', errors='ignore')
                i += host_len
            elif atyp == 3:
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}' 
                              for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            
            if is_blocked_domain(host):
                await websocket.close()
                return False
            
            await websocket.send_bytes(bytes([0, 0]))
            resolved_host = await resolve_host(host)
            
            try:
                # Add connection timeout (10s)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(resolved_host, port), 
                    timeout=10.0
                )
            except Exception as e:
                if DEBUG:
                    logger.error(f"Failed to connect to {resolved_host}:{port} -> {e}")
                return False

            if i < len(first_msg):
                writer.write(first_msg[i:])
                await writer.drain()

            async def forward_ws_to_tcp():
                try:
                    async for msg in websocket:
                        if msg.type == aiohttp.WSMsgType.BINARY:
                            writer.write(msg.data)
                            await writer.drain()
                        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            break
                except Exception:
                    pass
                finally:
                    writer.close()

            async def forward_tcp_to_ws():
                try:
                    while True:
                        data = await reader.read(8192)
                        if not data:
                            break
                        await websocket.send_bytes(data)
                except Exception:
                    pass

            # FIRST_COMPLETED: Ensures both tasks cancel as soon as one stops
            done, pending = await asyncio.wait(
                [
                    asyncio.create_task(forward_ws_to_tcp()),
                    asyncio.create_task(forward_tcp_to_ws())
                ],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            for task in pending:
                task.cancel()

            writer.close()
            await writer.wait_closed()
            return True

        except Exception as e:
            if DEBUG:
                logger.error(f"VLESS handler error: {e}")
            return False

async def websocket_handler(request):
    ws = web.WebSocketResponse(heartbeat=30.0)
    await ws.prepare(request)
    
    CUUID = UUID.replace('-', '')
    path = request.path
    
    if f'/{WSPATH}' not in path:
        await ws.close()
        return ws
    
    proxy = ProxyHandler(CUUID)
    
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        
        msg_data = first_msg.data
        
        if len(msg_data) > 17 and msg_data[0] == 0:
            await proxy.handle_vless(ws, msg_data)
        
    except Exception as e:
        if DEBUG:
            logger.error(f"WebSocket handler error: {e}")
    finally:
        if not ws.closed:
            await ws.close()
    
    return ws

async def http_handler(request):
    if request.path == '/':
        try:
            if os.path.exists('index.html'):
                with open('index.html', 'r', encoding='utf-8') as f:
                    content = f.read()
                return web.Response(text=content, content_type='text/html')
        except Exception:
            pass
        return web.Response(text='Hello world!', content_type='text/html')
    
    elif request.path == f'/{SUB_PATH}':
        await get_isp()
        await get_ip()
        
        name_part = f"{NAME}-{ISP}" if NAME else ISP
        tls_param = 'tls' if Tls == 'tls' else 'none'
        
        vless_url = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={tls_param}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{name_part}"
        base64_content = base64.b64encode(vless_url.encode()).decode()
        
        return web.Response(text=base64_content + '\n', content_type='text/plain')
    
    return web.Response(status=404, text='Not Found\n')

async def on_startup(app):
    global http_session
    http_session = aiohttp.ClientSession()

async def on_cleanup(app):
    global http_session
    if http_session and not http_session.closed:
        await http_session.close()

async def main():
    app = web.Application()
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    logger.info(f"Server started on port {PORT}")
    
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    # Graceful shutdown handlers for SIGTERM/SIGINT
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    try:
        await stop_event.wait()
    finally:
        logger.info("Stopping server gracefully...")
        await runner.cleanup()
        logger.info("Server completely stopped.")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("\nServer execution terminated.")
