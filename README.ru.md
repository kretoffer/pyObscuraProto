# pyObscuraProto

Python-обёртка для C++ библиотеки [ObscuraProto](https://github.com/anomalyco/ObscuraProto) — сквозное шифрование поверх WebSocket.

## Возможности

- **Сквозное шифрование** — протокол Noise (NX pattern) на базе libsodium
- **Аутентификация сервера** — долговременная ключевая пара для подписи, клиент проверяет публичный ключ сервера
- **Автоматическое согласование версий** — клиент и сервер договариваются о версии протокола во время handshake
- **Билдер/ридер бинарных payload'ов** — type-safe fluent API (`PayloadBuilder` / `PayloadReader`)
- **Автоматическая распаковка** — параметры payload'а распаковываются по type hints Python
- **Двунаправленный стриминг** — мультиплексированные потоки данных поверх одного зашифрованного соединения
- **Полная типизация** — все аннотации типов Python, проверка через pyright
- **Высокая производительность** — C++ ядро через pybind11, GIL освобождается во время I/O

## Установка

```bash
pip install pyObscuraProto
```

### Сборка из исходников

```bash
git clone --recurse-submodules https://github.com/anomalyco/pyObscuraProto.git
cd pyObscuraProto
python -m venv .venv && source .venv/bin/activate
pip install cmake
pip install -e .
```

Требуется CMake 3.14+, компилятор C++17 и libsodium (`brew install libsodium` на macOS, `apt install libsodium-dev` на Linux).

## Быстрый старт

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

Больше примеров в [examples/](examples/).

## Streaming API

Двунаправленные мультиплексированные потоки поверх одного зашифрованного соединения.

```python
import ObscuraProto as op

op.Crypto.init()

# --- Сервер ---
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

# --- Клиент ---
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

Полный пример: [examples/streaming_example.py](examples/streaming_example.py)

## Справочник API

| Класс / Функция | Описание |
|---|---|
| `Server` | Зашифрованный WebSocket-сервер. Декораторы: `@on_payload(opcode)`, `@on_request(opcode)`, `@on_incoming_stream`, `@default_payload_handler` |
| `Client(server_pk)` | Зашифрованный WebSocket-клиент. Декораторы: `@on_ready`, `@on_disconnect`, `@on_payload(opcode)`, `@on_request(opcode)`, `@on_incoming_stream` |
| `Stream` | Двунаправленный поток данных. Декораторы: `@on_data`, `@on_end`, `@on_cancel`. I/O: `write()`, `end()`, `cancel()`, `async_write()`, `async_end()`, `async_cancel()` |
| `PayloadBuilder(opcode)` | Сборка бинарных payload'ов. `add_param(str / int / uint / bool / float / bytes)`, `.build()` |
| `PayloadReader(payload)` | Чтение бинарных payload'ов. `read_string()`, `read_int()`, `read_uint()`, `read_bool()`, `read_float()`, `read_bytes()` |
| `Payload` | Сырой payload с полями `.op_code` и `.parameters`. Есть `.serialize()` / `Payload.deserialize()` |
| `uint` | Маркер типа: `def handler(value: uint)` читает параметр как беззнаковое целое |
| `Crypto` | Статические криптооперации: `init()`, `generate_kx_keypair()`, `generate_sign_keypair()`, `sign()`, `verify()`, `encrypt()`, `decrypt()` |
| `KeyPair` / `PublicKey` / `PrivateKey` | Типы ключей с полем `.data` |
| `ConnectionHdl` | Непрозрачный идентификатор соединения для адресации конкретных клиентов |

## Примеры

| Пример | Описание |
|---|---|
| [python_websocket_example.py](examples/python_websocket_example.py) | Минимальный send/response с авто-распаковкой |
| [request_response_example/](examples/request_response_example/) | Паттерн запрос-ответ (async сервер + клиент) |
| [streaming_example.py](examples/streaming_example.py) | Двунаправленный стриминг echo |

## Разработка

```bash
source .venv/bin/activate
pip install -e .
pre-commit install
```

- **Ruff** — линтинг и форматирование
- **Pyright** — проверка типов
- **pytest** — тестирование (`python -m pytest tests/`)
- **Pre-commit** — автоматические проверки перед каждым коммитом

Полные правила в [CONTRIBUTING.md](CONTRIBUTING.md).

## Лицензия

MIT © 2025 Kretov Artem. Подробнее в [LICENSE](LICENSE).
