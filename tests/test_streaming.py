"""
End-to-end tests for the bidirectional streaming API.
"""

import os
import sys
import threading
import time

import pytest

src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, src_dir)

try:
    import ObscuraProto as op
except ImportError as e:
    pytest.fail(f"Could not import the ObscuraProto package: {e}. Searched in: {sys.path}", pytrace=False)

PORT = 9005


@pytest.fixture(scope="module")
def crypto_init():
    op.Crypto.init()


def test_bidirectional_streaming(crypto_init, capsys):
    """
    Tests a full bidirectional streaming flow:
        1. Server registers an incoming-stream handler (echo server).
        2. Client connects, starts an outgoing stream, writes chunks, ends.
        3. Server echoes data back, then ends.
        4. Verify all data arrived correctly on both sides.
    """
    # Synchronisation
    client_ready = threading.Event()
    stream_started = threading.Event()
    stream_ended = threading.Event()
    server_done = threading.Event()

    # Log received data for assertions
    server_chunks = []
    client_chunks = []

    # --- Server ---
    server = op.Server()

    @server.on_incoming_stream
    def handle_stream(stream: op.Stream):
        print(f"[SERVER] New incoming stream #{stream.stream_id}")

        @stream.on_data
        def on_data(data: bytes):
            print(f"[SERVER] Received {len(data)} bytes: {data}")
            server_chunks.append(data)
            stream.write(b"echo:" + data)

        @stream.on_end
        def on_end():
            print("[SERVER] Client finished writing")
            stream.end()
            server_done.set()

    # --- Client ---
    client = op.Client(server.public_key)

    @client.on_ready
    def on_ready():
        print("[CLIENT] Connected. Starting stream...")
        client_ready.set()
        stream = client.start_stream()

        @stream.on_data
        def on_client_data(data: bytes):
            print(f"[CLIENT] Received echo: {data}")
            client_chunks.append(data)

        @stream.on_end
        def on_end():
            print("[CLIENT] Server finished writing")
            stream_ended.set()

        stream.write(b"Hello ")
        stream.write(b"World!")
        stream_started.set()
        time.sleep(0.1)
        print("[CLIENT] Ending outgoing data")
        stream.end()

    # --- Test body ---
    try:
        server.start(PORT)
        time.sleep(0.1)
        client.connect(f"ws://localhost:{PORT}")

        assert client_ready.wait(timeout=5), "Client did not become ready"
        assert stream_started.wait(timeout=5), "Stream did not start"
        assert server_done.wait(timeout=5), "Server did not finish"
        assert stream_ended.wait(timeout=5), "Stream did not end (client side)"

        # Assertions
        assert len(server_chunks) == 2
        assert server_chunks[0] == b"Hello "
        assert server_chunks[1] == b"World!"

        assert len(client_chunks) == 2
        assert client_chunks[0] == b"echo:Hello "
        assert client_chunks[1] == b"echo:World!"

    finally:
        client.disconnect()
        server.stop()
        time.sleep(0.1)
        captured = capsys.readouterr()
        print(captured.out)
