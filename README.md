# pyObscuraProto

Python wrapper for the [ObscuraProto](https://github.com/anomalyco/ObscuraProto) C++ library — end-to-end encrypted communication over WebSocket.

## Features

- **End-to-end encryption** — Noise Protocol Framework (NX pattern) with libsodium
- **Server authentication** — long-term signing keypair, clients verify the server's public key
- **Automatic version negotiation** — client and server agree on protocol version during handshake
- **Binary payload builder/reader** — type-safe fluent API (`PayloadBuilder` / `PayloadReader`)
- **Auto-unpacking** — payload parameters are unpacked automatically based on Python type hints
- **Bidirectional streaming** — multiplexed data streams over a single encrypted connection
- **Fully typed** — complete Python type annotations; checked with pyright
- **High performance** — C++ core via pybind11, GIL released during I/O

## Installation

```bash
pip install pyObscuraProto
```

### Build from source

```bash
git clone --recurse-submodules https://github.com/anomalyco/pyObscuraProto.git
cd pyObscuraProto
python -m venv .venv && source .venv/bin/activate
pip install cmake
pip install -e .
```

Requires CMake 3.14+, C++17 compiler, and libsodium (`brew install libsodium` on macOS, `apt install libsodium-dev` on Linux).

## Quick Start

```python
import ObscuraProto as op

op.Crypto.init()

server = op.Server()
server.start(9001)

client = op.Client(server.public_key)
client.connect("ws://localhost:9001")

@client.on_ready
def on_ready():
    payload = op.PayloadBuilder(0x1001).add_param("hello").build()
    client.send(payload)
```

See [examples/](examples/) for more.

## Streaming API

Bidirectional multiplexed streams over a single encrypted connection.

```python
import ObscuraProto as op

op.Crypto.init()

# --- Server ---
server = op.Server()

@server.on_incoming_stream
def handle_stream(stream: op.Stream):
    @stream.on_data
    def on_data(data: bytes):
        stream.write(b"echo: " + data)

    @stream.on_end
    def on_end():
        stream.end()

server.start(9006)

# --- Client ---
client = op.Client(server.public_key)

@client.on_ready
def on_ready():
    stream = client.start_stream()

    @stream.on_data
    def on_data(data: bytes):
        print(f"Echo: {data}")

    stream.write(b"hello")
    stream.end()

client.connect("ws://localhost:9006")
```

Full example: [examples/streaming_example.py](examples/streaming_example.py)

## API Reference

| Class / Function | Description |
|---|---|
| `Server` | Encrypted WebSocket server. Decorators: `@on_payload(opcode)`, `@on_request(opcode)`, `@on_incoming_stream`, `@default_payload_handler` |
| `Client(server_pk)` | Encrypted WebSocket client. Decorators: `@on_ready`, `@on_disconnect`, `@on_payload(opcode)`, `@on_request(opcode)`, `@on_incoming_stream` |
| `Stream` | Bidirectional data stream. Decorators: `@on_data`, `@on_end`, `@on_cancel`. I/O: `write()`, `end()`, `cancel()`, `async_write()`, `async_end()`, `async_cancel()` |
| `PayloadBuilder(opcode)` | Build binary payloads. `add_param(str / int / uint / bool / float / bytes)`, `.build()` |
| `PayloadReader(payload)` | Read binary payloads. `read_string()`, `read_int()`, `read_uint()`, `read_bool()`, `read_float()`, `read_bytes()` |
| `Payload` | Raw payload with `.op_code` and `.parameters`. Has `.serialize()` / `Payload.deserialize()` |
| `uint` | Type hint marker: `def handler(value: uint)` reads the parameter as unsigned |
| `Crypto` | Static crypto: `init()`, `generate_kx_keypair()`, `generate_sign_keypair()`, `sign()`, `verify()`, `encrypt()`, `decrypt()` |
| `KeyPair` / `PublicKey` / `PrivateKey` | Key types with `.data` field |
| `ConnectionHdl` | Opaque connection handle for targeting specific clients |

## Examples

| Example | Description |
|---|---|
| [python_websocket_example.py](examples/python_websocket_example.py) | Minimal send/response with auto-unpacking |
| [request_response_example/](examples/request_response_example/) | Request-response pattern (async server + client) |
| [streaming_example.py](examples/streaming_example.py) | Bidirectional streaming echo |

## Development

```bash
source .venv/bin/activate
pip install -e .
pre-commit install
```

- **Ruff** — linting & formatting
- **Pyright** — type checking
- **pytest** — testing (`python -m pytest tests/`)
- **Pre-commit** — runs checks before every commit

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

## License

MIT © 2025 Kretov Artem. See [LICENSE](LICENSE).
