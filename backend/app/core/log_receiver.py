import asyncio
import json
import struct
import zlib
from loguru import logger
from app.config import get_settings
from app.pipeline.ingestion_pipeline import pipeline

settings = get_settings()

class WinlogbeatReceiver:
    def __init__(self, host='0.0.0.0', port=None):
        self.host = host
        self.port = port or settings.winlogbeat_port
        self.server = None
        self._connections = 0
        self._total_received = 0

    async def start(self):
        try:
            self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
            logger.success(f"🔵 Winlogbeat receiver listening on {self.host}:{self.port}")
            asyncio.create_task(self._serve())
        except Exception as e:
            logger.error(f"❌ Failed to start Winlogbeat receiver: {e}")

    async def _serve(self):
        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        self._connections += 1
        logger.info(f"🔗 New connection from {addr} (total: {self._connections})")
        try:
            await self._handle_lumberjack(reader, writer, addr)
        except Exception as e:
            logger.debug(f"Client error: {e}")
        finally:
            self._connections -= 1
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_lumberjack(self, reader, writer, addr):
        seq = 0
        while True:
            try:
                header = await asyncio.wait_for(reader.read(2), timeout=60.0)
            except asyncio.TimeoutError:
                break
            if not header or len(header) < 2:
                break
            version = header[0]
            frame_type = chr(header[1])
            if version == ord('2') and frame_type == 'W':
                await reader.read(4)
            elif version == ord('2') and frame_type == 'C':
                size_data = await reader.read(4)
                if len(size_data) < 4:
                    break
                compressed_size = struct.unpack('>I', size_data)[0]
                compressed = b''
                remaining = compressed_size
                while remaining > 0:
                    chunk = await reader.read(min(remaining, 65536))
                    if not chunk:
                        break
                    compressed += chunk
                    remaining -= len(chunk)
                try:
                    decompressed = zlib.decompress(compressed)
                    events = self._parse_frames(decompressed)
                    for event in events:
                        seq += 1
                        await self._process_event(event, addr)
                        self._total_received += 1
                    ack = struct.pack('>ccI', b'2', b'A', seq)
                    writer.write(ack)
                    await writer.drain()
                    if self._total_received % 10 == 0:
                        logger.info(f"📩 Winlogbeat events received: {self._total_received}")
                except Exception as e:
                    logger.debug(f"Frame error: {e}")
            else:
                await reader.read(4096)
                break

    def _parse_frames(self, data):
        events = []
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                break
            frame_type = chr(data[offset + 1])
            offset += 2
            if frame_type == 'J':
                if offset + 8 > len(data):
                    break
                json_len = struct.unpack('>I', data[offset+4:offset+8])[0]
                offset += 8
                if offset + json_len > len(data):
                    break
                try:
                    event = json.loads(data[offset:offset+json_len].decode('utf-8', errors='replace'))
                    events.append(event)
                except Exception:
                    pass
                offset += json_len
            elif frame_type == 'D':
                if offset + 8 > len(data):
                    break
                pair_count = struct.unpack('>I', data[offset+4:offset+8])[0]
                offset += 8
                event = {}
                for _ in range(pair_count):
                    if offset + 4 > len(data):
                        break
                    key_len = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    key = data[offset:offset+key_len].decode('utf-8', errors='replace')
                    offset += key_len
                    if offset + 4 > len(data):
                        break
                    val_len = struct.unpack('>I', data[offset:offset+4])[0]
                    offset += 4
                    val = data[offset:offset+val_len].decode('utf-8', errors='replace')
                    offset += val_len
                    event[key] = val
                if event:
                    try:
                        parsed = json.loads(event.get('message', '{}'))
                        events.append(parsed)
                    except Exception:
                        events.append({'source': 'winlogbeat', 'hostname': event.get('beat.hostname', 'unknown'), 'message': event.get('message', ''), 'log_level': 'INFO', 'raw': event})
            else:
                break
        return events

    async def _process_event(self, event, addr):
        try:
            await pipeline.ingest(event)
            logger.debug(f"🔵 Event queued from Winlogbeat")
        except Exception as e:
            logger.error(f"Event error: {e}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    def get_stats(self):
        return {'connections': self._connections, 'total_received': self._total_received}

class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver):
        self.receiver = receiver

    def datagram_received(self, data, addr):
        try:
            line = data.decode('utf-8', errors='replace').strip()
            self.receiver._total_received += 1
            # Ingest as raw syslog for auto_parse
            asyncio.create_task(pipeline.ingest({"raw_line": line, "source": "syslog", "remote_addr": addr[0]}))
            if self.receiver._total_received % 10 == 0:
                logger.info(f"📁 Syslog events received: {self.receiver._total_received}")
        except Exception as e:
            logger.error(f"Syslog receiver error: {e}")

class SyslogReceiver:
    def __init__(self, host='0.0.0.0', port=None):
        self.host = host
        self.port = port or settings.syslog_port
        self.transport = None
        self._total_received = 0

    async def start(self):
        try:
            loop = asyncio.get_running_loop()
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self),
                local_addr=(self.host, self.port)
            )
            logger.success(f"🚀 Syslog receiver listening on {self.host}:{self.port} (UDP)")
        except Exception as e:
            logger.error(f"❌ Failed to start Syslog receiver: {e}")

    async def stop(self):
        if self.transport:
            self.transport.close()

    def get_stats(self):
        return {"total_received": self._total_received}

receiver = WinlogbeatReceiver()
syslog_receiver = SyslogReceiver()
