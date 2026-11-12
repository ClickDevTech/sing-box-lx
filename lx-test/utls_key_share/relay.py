#!/usr/bin/env python3
"""SPEC 156 stand relay: forwards TCP and prints the size of the first TLS record.

    relay.py LISTEN_PORT TARGET_PORT

Each accepted connection prints one line, "clienthello <bytes>", where <bytes> is
the first TLS record including its 5-byte header, i.e. the ClientHello on the wire.
Loopback only.
"""
import asyncio
import sys


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


async def handle(client_reader, client_writer, target_port):
    try:
        header = await client_reader.readexactly(5)
        body = await client_reader.readexactly(int.from_bytes(header[3:5], "big"))
    except asyncio.IncompleteReadError:
        client_writer.close()
        return
    print(f"clienthello {len(header) + len(body)}", flush=True)
    server_reader, server_writer = await asyncio.open_connection("127.0.0.1", target_port)
    server_writer.write(header + body)
    await asyncio.gather(pipe(client_reader, server_writer), pipe(server_reader, client_writer))


async def main():
    listen_port, target_port = int(sys.argv[1]), int(sys.argv[2])
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, target_port), "127.0.0.1", listen_port)
    async with server:
        await server.serve_forever()


asyncio.run(main())
