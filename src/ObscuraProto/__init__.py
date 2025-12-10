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
    
    # The compiled library is directly in the build directory now
    if os.path.isdir(build_dir):
        sys.path.insert(0, build_dir)

    try:
        # The module name includes version and platform info, so we search for it.
        if os.path.isdir(build_dir):
            for f in os.listdir(build_dir):
                if f.startswith("_obscuraproto") and f.endswith(".so"):
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("_obscuraproto", os.path.join(build_dir, f))
                    _bindings = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(_bindings)
                    sys.modules['_obscuraproto'] = _bindings
                    break
            else:
                raise ImportError("Could not find the _obscuraproto.*.so module in the build directory.")
        else:
             raise ImportError("Build directory not found.")
             
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
ConnectionHdl = _bindings.ConnectionHdl


# --- High-level wrapper classes ---

class Server:
    """
    An ObscuraProto WebSocket server.
    
    This class wraps the C++ WsServer to provide a Pythonic interface with
    decorators for handling events.
    """
    def __init__(self):
        """Initializes the server, generating its long-term signing key."""
        self._long_term_key = _bindings.Crypto.generate_sign_keypair()
        self._server = _bindings.WsServer(self._long_term_key)

    @property
    def public_key(self):
        """The server's long-term public key, needed by clients to connect."""
        return self._long_term_key.public_key

    def start(self, port):
        """
        Starts the WebSocket server on the given port.
        This runs the server in a background thread.
        """
        print(f"[PY-SERVER] Starting on port {port}...")
        self._server.run(port)
        print(f"[PY-SERVER] Started.")

    def stop(self):
        """Stops the server."""
        print("[PY-SERVER] Stopping...")
        self._server.stop()
        print("[PY-SERVER] Stopped.")

    def send(self, hdl, payload):
        """Sends a payload to a specific client."""
        self._server.send(hdl, payload)

    def on_payload(self, opcode):
        """
        Decorator to register a handler for a specific opcode.
        
        The decorated function will be called with the connection handle and the payload.
        
        Example:
            server = Server()
            @server.on_payload(0x1001)
            def handle_login(hdl, payload):
                print("Received login payload")
        """
        def decorator(handler):
            # The C++ layer expects a function with a specific signature.
            # We register a lambda that calls the user's decorated function.
            self._server.register_op_handler(opcode, lambda h, p: handler(h, p))
            return handler
        return decorator

    def default_payload_handler(self, handler):
        """
        Decorator to register a default handler for unhandled opcodes.
        """
        self._server.set_default_payload_handler(lambda h, p: handler(h, p))
        return handler


class Client:
    """
    An ObscuraProto WebSocket client.

    Wraps the C++ WsClient for a Pythonic interface with decorators.
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
        self._client = _bindings.WsClient(key_view)

    def connect(self, uri):
        """Connects to the server at the given WebSocket URI (e.g., "ws://localhost:9002")."""
        print(f"[PY-CLIENT] Connecting to {uri}...")
        self._client.connect(uri)

    def disconnect(self):
        """Disconnects from the server."""
        self._client.disconnect()

    def send(self, payload):
        """Sends a payload to the server."""
        self._client.send(payload)

    def on_ready(self, handler):
        """Decorator to register a callback for when the client is connected and ready."""
        self._client.set_on_ready_callback(handler)
        return handler

    def on_disconnect(self, handler):
        """Decorator to register a callback for when the client disconnects."""
        self._client.set_on_disconnect_callback(handler)
        return handler

    def on_payload(self, opcode):
        """
        Decorator to register a handler for a specific opcode from the server.
        
        Example:
            @client.on_payload(0x2001)
            def handle_chat_message(payload):
                ...
        """
        def decorator(handler):
            self._client.register_op_handler(opcode, lambda p: handler(p))
            return handler
        return decorator

    def default_payload_handler(self, handler):
        """
        Decorator to register a default handler for unhandled server opcodes.
        """
        self._client.set_default_payload_handler(lambda p: handler(p))
        return handler

