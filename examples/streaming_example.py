"""
Bidirectional streaming over ObscuraProto.

Demonstrates:
  - Server: @on_incoming_stream decorator with echo logic
  - Client: start_stream(), @stream.on_data, @stream.on_end decorators
  - Half-close: client ends its write side, server echoes end
"""

import time

import ObscuraProto as op

op.Crypto.init()

server = op.Server()


# ---- Server ----
@server.on_incoming_stream
def handle_stream(stream: op.Stream):
    print(f"[SERVER] New incoming stream #{stream.stream_id}")

    @stream.on_data
    def on_data(data: bytes):
        print(f"[SERVER] Received {len(data)} bytes: {data}")
        stream.write(b"echo: " + data)

    @stream.on_end
    def on_end():
        print("[SERVER] Client finished writing, echoing end")
        stream.end()


server.start(9006)
time.sleep(0.1)

# ---- Client ----
client = op.Client(server.public_key)


@client.on_ready
def on_ready():
    print("[CLIENT] Connected. Starting stream...")
    stream = client.start_stream()

    @stream.on_data
    def on_data(data: bytes):
        print(f"[CLIENT] Echo received: {data}")

    @stream.on_end
    def on_end():
        print("[CLIENT] Server finished writing")

    stream.write(b"Hello ")
    stream.write(b"streaming ")
    stream.write(b"world!")
    time.sleep(0.2)
    stream.end()
    print("[CLIENT] Done writing")


client.connect("ws://localhost:9006")
time.sleep(1)

# ---- Cleanup ----
client.disconnect()
server.stop()
print("\nDone.")
