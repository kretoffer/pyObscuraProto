"""
ObscuraProto high-level Python library.
"""
try:
    # This is the C++ extension module built by CMake.
    from . import _obscuraproto as _bindings
except ImportError:
    # If the extension is not in the same directory, it might be in the build/lib directory.
    # This is a fallback for development environments. For a real installation,
    # the package structure would handle this.
    import sys
    import os
    
    # Heuristic to find the build directory.
    # Assumes the project root is two levels up from this file's directory.
    proj_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    build_dir = os.path.join(proj_root, 'build')
    lib_dir = os.path.join(build_dir, 'lib')
    
    if os.path.isdir(lib_dir):
         sys.path.insert(0, lib_dir)
    elif os.path.isdir(build_dir):
        sys.path.insert(0, build_dir)

    try:
        import _obscuraproto as _bindings
    except ImportError as e:
        raise ImportError(
            "Could not import the compiled ObscuraProto C++ bindings (_obscuraproto). "
            "Please make sure the project is built. "
            f"Original error: {e}"
        )


# --- Re-export low-level components ---
Role = _bindings.Role
Crypto = _bindings.Crypto
Payload = _bindings.Payload
PayloadBuilder = _bindings.PayloadBuilder
PayloadReader = _bindings.PayloadReader
KeyPair = _bindings.KeyPair
PublicKey = _bindings.PublicKey
PrivateKey = _bindings.PrivateKey
V1_0 = _bindings.V1_0
SUPPORTED_VERSIONS = _bindings.SUPPORTED_VERSIONS


# --- High-level wrapper classes ---

class _BasePeer:
    """
    An internal base class for Client and Server peers, providing common functionality.
    """
    def __init__(self, session):
        if not isinstance(session, _bindings.Session):
            raise TypeError("session must be a _bindings.Session object")
        self._session = session
        self.peer = None

    def register_op_handler(self, opcode, handler):
        """Registers a handler for a specific opcode."""
        self._session.register_op_handler(opcode, handler)

    def set_default_payload_handler(self, handler):
        """Sets the default handler for unhandled opcodes."""
        self._session.set_default_payload_handler(handler)

    def _receive_encrypted(self, packet):
        """Internal method to receive and decrypt a packet."""
        self._session.decrypt_packet(packet)
    
    def send(self, payload):
        """
        Encrypts and sends a payload to the connected peer.
        
        Raises:
            RuntimeError: If the handshake is not complete or the peer is not connected.
        """
        if not self._session.is_handshake_complete():
            raise RuntimeError("Handshake must be complete before sending data.")
        if not self.peer:
            raise RuntimeError("Peer is not connected.")
            
        encrypted_packet = self._session.encrypt_payload(payload)
        self.peer._receive_encrypted(encrypted_packet)


class Server(_BasePeer):
    """
    Represents a Server peer in a simulated ObscuraProto connection.
    It holds its own long-term keys and session.
    """
    def __init__(self):
        long_term_key = _bindings.Crypto.generate_sign_keypair()
        session = _bindings.Session(_bindings.Role.SERVER, long_term_key)
        super().__init__(session)
        self._long_term_key = long_term_key

    @property
    def public_key(self):
        """The server's long-term public key, needed by clients to connect."""
        return self._long_term_key.public_key


class Client(_BasePeer):
    """
    Represents a Client peer in a simulated ObscuraProto connection.
    """
    def __init__(self, server_public_key):
        """
        Args:
            server_public_key: The public key of the server to connect to.
        """
        if not isinstance(server_public_key, _bindings.PublicKey):
            raise TypeError("server_public_key must be a PublicKey object.")
            
        key_view = _bindings.KeyPair()
        key_view.public_key = server_public_key
        session = _bindings.Session(_bindings.Role.CLIENT, key_view)
        super().__init__(session)
        self._on_ready_callback = None

    def set_on_ready_callback(self, callback):
        """

        Sets a callback to be fired when the handshake is successfully completed.
        """
        self._on_ready_callback = callback

    def connect(self, server_peer):
        """
        Connects to a server peer and performs the handshake under the hood.

        Args:
            server_peer (Server): The server instance to connect to.
        """
        if not isinstance(server_peer, Server):
            raise TypeError("server_peer must be a Server object.")

        print("[SYSTEM] Initiating connection and performing handshake...")
        self.peer = server_peer
        server_peer.peer = self
        
        # Perform the 3-step handshake
        client_hello = self._session.client_initiate_handshake()
        # In this simulation, we pass the data directly.
        # In a real network, this would be sent over a transport.
        server_hello = server_peer._session.server_respond_to_handshake(client_hello)
        self._session.client_finalize_handshake(server_hello)
        
        if self._session.is_handshake_complete():
            print("[SYSTEM] Handshake complete.")
            if self._on_ready_callback:
                self._on_ready_callback()
        else:
            print("[SYSTEM] Handshake failed.")

