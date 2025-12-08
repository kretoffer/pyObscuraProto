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

def test_high_level_opcode_callbacks(crypto_init, capsys):
    """
    Tests the high-level Client/Server wrappers and the opcode callback system.
    """
    # --- Shared state for verifying handler calls ---
    server_received_payloads = []
    client_received_payloads = []
    server_responses_to_send = []
    client_is_ready = False

    # --- Callbacks and Handlers ---
    def on_client_ready():
        nonlocal client_is_ready
        client_is_ready = True

    def handler_get_status(payload):
        server_received_payloads.append(payload)
        response_payload = op.PayloadBuilder(0x6001).add_param("Server is OK").build()
        server_responses_to_send.append(response_payload)

    def handler_echo(payload):
        server_received_payloads.append(payload)
        server_responses_to_send.append(payload) # Echo back

    def default_server_handler(payload):
        server_received_payloads.append(payload)

    def default_client_handler(payload):
        client_received_payloads.append(payload)

    # 1. Create Server and Client instances
    server = op.Server()
    client = op.Client(server.public_key)

    # 2. Register handlers and callbacks
    server.register_op_handler(OP_GET_STATUS, handler_get_status)
    server.register_op_handler(OP_ECHO, handler_echo)
    server.set_default_payload_handler(default_server_handler)
    
    client.set_default_payload_handler(default_client_handler)
    client.set_on_ready_callback(on_client_ready)

    # 3. Connect client to server (handshake happens automatically)
    client.connect(server)
    assert client_is_ready

    # 4. Client sends messages to the server
    print("\n[CLIENT] Sending messages...")
    client.send(op.PayloadBuilder(OP_GET_STATUS).build())
    client.send(op.PayloadBuilder(OP_ECHO).add_param("echo this!").build())
    client.send(op.PayloadBuilder(OP_UNHANDLED).build())
    
    # 5. Verify server received all messages
    assert len(server_received_payloads) == 3
    assert server_received_payloads[0].op_code == OP_GET_STATUS
    assert server_received_payloads[1].op_code == OP_ECHO
    assert server_received_payloads[2].op_code == OP_UNHANDLED

    # 6. Server sends collected responses back to the client
    print("\n[SERVER] Sending responses...")
    assert len(server_responses_to_send) == 2
    for response_payload in server_responses_to_send:
        server.send(response_payload)

    # 7. Verify client received the responses
    assert len(client_received_payloads) == 2
    
    # Check OP_GET_STATUS response
    assert client_received_payloads[0].op_code == 0x6001
    reader1 = op.PayloadReader(client_received_payloads[0])
    assert reader1.read_string() == "Server is OK"
    
    # Check OP_ECHO response
    assert client_received_payloads[1].op_code == OP_ECHO
    reader2 = op.PayloadReader(client_received_payloads[1])
    assert reader2.read_string() == "echo this!"

    captured = capsys.readouterr()
    print(captured.out)
    print("\n[SYSTEM] High-level API test complete.")