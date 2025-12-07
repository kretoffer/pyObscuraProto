import sys
import os
import pytest

# Add build directory to path to find the compiled module.
build_dir = os.path.abspath('build')
lib_dir = os.path.join(build_dir, 'lib')

# In some cases, the .so file is directly in 'build', in others, it's in 'build/lib'
sys.path.insert(0, build_dir)
if os.path.isdir(lib_dir):
    sys.path.insert(0, lib_dir)

try:
    import ObscuraProto as op
except ImportError as e:
    pytest.fail(f"Could not import ObscuraProto: {e}. Make sure it's built. Searched in: {sys.path}", pytrace=False)


@pytest.fixture(scope="module")
def crypto_init():
    """Fixture to ensure Crypto is initialized only once per module."""
    op.Crypto.init()

@pytest.fixture
def server_keys():
    """Fixture to generate and provide server signing keys."""
    return op.Crypto.generate_sign_keypair()

def test_session_creation(crypto_init, server_keys):
    """Tests that client and server Session objects can be created."""
    # Client needs the server's public key
    client_server_key_view = op.KeyPair()
    client_server_key_view.public_key = server_keys.public_key

    client_session = op.Session(op.Role.CLIENT, client_server_key_view)
    assert client_session is not None
    assert not client_session.is_handshake_complete()

    # Server needs its full keypair
    server_session = op.Session(op.Role.SERVER, server_keys)
    assert server_session is not None
    assert not server_session.is_handshake_complete()


def test_full_handshake(crypto_init, server_keys):
    """Tests the full client-server handshake process."""
    client_server_key_view = op.KeyPair()
    client_server_key_view.public_key = server_keys.public_key

    client = op.Session(op.Role.CLIENT, client_server_key_view)
    server = op.Session(op.Role.SERVER, server_keys)

    # 1. Client initiates
    client_hello = client.client_initiate_handshake()
    assert isinstance(client_hello, op.ClientHello)

    # 2. Server responds
    server_hello = server.server_respond_to_handshake(client_hello)
    assert isinstance(server_hello, op.ServerHello)

    # 3. Client finalizes
    client.client_finalize_handshake(server_hello)

    # 4. Verify handshake is complete on both ends
    assert client.is_handshake_complete()
    assert server.is_handshake_complete()
    
    # Verify they negotiated the same version
    assert client.get_selected_version() == server.get_selected_version()
    assert client.get_selected_version() is not None


def test_encryption_decryption(crypto_init, server_keys):
    """Tests that data can be encrypted and decrypted after a handshake."""
    client_server_key_view = op.KeyPair()
    client_server_key_view.public_key = server_keys.public_key
    
    client = op.Session(op.Role.CLIENT, client_server_key_view)
    server = op.Session(op.Role.SERVER, server_keys)

    # Perform handshake first
    client_hello = client.client_initiate_handshake()
    server_hello = server.server_respond_to_handshake(client_hello)
    client.client_finalize_handshake(server_hello)
    
    assert client.is_handshake_complete()
    assert server.is_handshake_complete()

    # Client to Server
    builder_c2s = op.PayloadBuilder(101)
    builder_c2s.add_param("Hello from client!")
    builder_c2s.add_param(12345)
    payload_c2s = builder_c2s.build()

    encrypted_c2s = client.encrypt_payload(payload_c2s)
    decrypted_payload_c2s = server.decrypt_packet(encrypted_c2s)

    assert decrypted_payload_c2s.op_code == payload_c2s.op_code
    
    reader_c2s = op.PayloadReader(decrypted_payload_c2s)
    assert reader_c2s.read_string() == "Hello from client!"
    assert reader_c2s.read_int() == 12345
    assert not reader_c2s.has_more()

    # Server to Client
    builder_s2c = op.PayloadBuilder(202)
    builder_s2c.add_param("Response from server.")
    builder_s2c.add_param(True)
    payload_s2c = builder_s2c.build()

    encrypted_s2c = server.encrypt_payload(payload_s2c)
    decrypted_payload_s2c = client.decrypt_packet(encrypted_s2c)

    assert decrypted_payload_s2c.op_code == payload_s2c.op_code

    reader_s2c = op.PayloadReader(decrypted_payload_s2c)
    assert reader_s2c.read_string() == "Response from server."
    assert reader_s2c.read_bool() is True
    assert not reader_s2c.has_more()