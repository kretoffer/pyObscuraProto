import sys
import os
import pytest

# Add the src directory to the path to find the ObscuraProto package
src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, src_dir)

try:
    import ObscuraProto as op
except ImportError as e:
    pytest.fail(f"Could not import the ObscuraProto package: {e}. Searched in: {sys.path}", pytrace=False)

# Opcodes for our example
OP_GET_STATUS = 0x5001
OP_ECHO = 0x5002
OP_UNHANDLED = 0x5003

@pytest.fixture(scope="module")
def crypto_init():
    """Fixture to ensure Crypto is initialized only once per module."""
    op.Crypto.init()

import sys
import os
import pytest
import asyncio

# Add the src directory to the path to find the ObscuraProto package
src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, src_dir)

try:
    import ObscuraProto as op
except ImportError as e:
    pytest.fail(f"Could not import the ObscuraProto package: {e}. Searched in: {sys.path}", pytrace=False)

# Opcodes for our example
OP_GET_STATUS = 0x5001
OP_ECHO = 0x5002
OP_UNHANDLED = 0x5003

@pytest.fixture(scope="module")
def crypto_init():
    """Fixture to ensure Crypto is initialized only once per module."""
    op.Crypto.init()

@pytest.mark.asyncio
async def test_high_level_opcode_callbacks(crypto_init, capsys):
    """
    Tests the high-level Client/Server wrappers and the opcode callback system.
    """
    server_received_payloads = []
    client_received_payloads = []
    server_responses_to_send = []
    client_is_ready = False

    server = op.Server()
    client = op.Client(server.public_key)

    try:
        async def on_client_ready():
            nonlocal client_is_ready
            client_is_ready = True

        @server.handle_op_code(OP_GET_STATUS)
        async def handler_get_status(payload):
            server_received_payloads.append(payload)
            response_payload = op.PayloadBuilder(0x6001).add_param("Server is OK").build()
            await server.send(response_payload)

        @server.handle_op_code(OP_ECHO)
        async def handler_echo(payload):
            server_received_payloads.append(payload)
            await server.send(payload)  # Echo back

        @server.default_handler
        async def default_server_handler(payload):
            server_received_payloads.append(payload)

        @client.default_handler
        async def default_client_handler(payload):
            client_received_payloads.append(payload)

        client.set_on_ready_callback(on_client_ready)

        await client.connect(server)
        assert client_is_ready

        print("\n[CLIENT] Sending messages...")
        await client.send(op.PayloadBuilder(OP_GET_STATUS).build())
        await client.send(op.PayloadBuilder(OP_ECHO).add_param("echo this!").build())
        await client.send(op.PayloadBuilder(OP_UNHANDLED).build())

        # Give the event loop time to process all messages
        await asyncio.sleep(0.01)

        assert len(server_received_payloads) == 3
        assert server_received_payloads[0].op_code == OP_GET_STATUS
        assert server_received_payloads[1].op_code == OP_ECHO
        assert server_received_payloads[2].op_code == OP_UNHANDLED

        # Give the event loop time to process server responses
        await asyncio.sleep(0.01)

        assert len(client_received_payloads) == 2
        
        # Sort by opcode to ensure consistent order
        client_received_payloads.sort(key=lambda p: p.op_code)

        assert client_received_payloads[0].op_code == OP_ECHO
        reader2 = op.PayloadReader(client_received_payloads[0])
        assert reader2.read_string() == "echo this!"

        assert client_received_payloads[1].op_code == 0x6001
        reader1 = op.PayloadReader(client_received_payloads[1])
        assert reader1.read_string() == "Server is OK"

        captured = capsys.readouterr()
        print(captured.out)
        print("\n[SYSTEM] High-level API test complete.")

    finally:
        server.close()
        client.close()