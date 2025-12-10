"""
ObscuraProto high-level Python library.
"""
import inspect

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

# --- Marker type for automatic unpacking ---
class uint(int):
    """A marker type for function signature hints. 
    Indicates that an integer parameter should be read from a payload as unsigned.
    
    Example:
        @server.on_payload(0x1234)
        def my_handler(value: uint):
            # value will be read using PayloadReader.read_uint()
            print(f"Received unsigned value: {value}")
    """
    pass

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


def _create_unpacking_handler(handler, is_server_handler=False):
    """
    Internal helper to create a wrapper function that unpacks a payload
    based on the handler's type hints.
    """
    sig = inspect.signature(handler)
    params = list(sig.parameters.values())
    
    # Determine which parameters to unpack based on signature
    hdl_offset = 1 if is_server_handler else 0
    params_to_unpack = params[hdl_offset:]

    # If there are no params to unpack, or if the first unpackable param is annotated as Payload,
    # or if there are no annotations at all, then fallback to raw payload handling.
    if not params_to_unpack or \
       params_to_unpack[0].annotation is Payload or \
       all(p.annotation is p.empty for p in params_to_unpack):
        
        if is_server_handler:
            return lambda h, p: handler(h, p)
        else:
            return lambda p: handler(p)

    # --- Create the unpacking wrapper ---
    def unpacking_wrapper(*args):
        payload = args[-1] # Payload is always the last argument from C++
        reader = PayloadReader(payload)
        
        type_map = {
            str: reader.read_string,
            int: reader.read_int,
            uint: reader.read_uint,
            float: reader.read_float, # Use the new universal float reader
            bool: reader.read_bool,
            bytes: reader.read_bytes,
        }
        
        unpacked_args = []
        if is_server_handler:
            unpacked_args.append(args[0]) # Prepend the connection handle

        try:
            for param in params_to_unpack:
                type_hint = param.annotation
                if type_hint in type_map:
                    unpacked_args.append(type_map[type_hint]())
                elif type_hint is param.empty:
                    raise TypeError(f"Missing type hint for parameter '{param.name}'. "
                                    "Cannot perform automatic payload unpacking.")
                else:
                    raise TypeError(f"Unsupported type hint '{type_hint}' for parameter '{param.name}'.")
        except Exception as e:
            op_code_hex = f"0x{payload.op_code:04x}" if payload else "N/A"
            print(f"[ERROR] Failed to auto-unpack payload for OpCode {op_code_hex}. "
                  f"Check that the handler signature for '{handler.__name__}' matches the payload structure. Details: {e}")
            return # Suppress further errors

        return handler(*unpacked_args)

    return unpacking_wrapper


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
        
        The decorated function will be called with arguments unpacked from the
        payload based on type hints. If no type hints are provided, it will be
        called with `(hdl, payload)`.

        Example:
            @server.on_payload(0x1001)
            def handle_login(hdl, username: str, password: str, attempt: uint):
                print(f"Login attempt for '{username}'")
        """
        def decorator(handler):
            wrapper = _create_unpacking_handler(handler, is_server_handler=True)
            self._server.register_op_handler(opcode, wrapper)
            return handler
        return decorator

    def default_payload_handler(self, handler):
        """
        Decorator for the default handler, with auto-unpacking based on type hints.
        """
        wrapper = _create_unpacking_handler(handler, is_server_handler=True)
        self._server.set_default_payload_handler(wrapper)
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
        
        The decorated function will be called with arguments unpacked from the
        payload based on type hints. If no type hints are provided, it will be
        called with the raw `payload` object.

        Example:
            @client.on_payload(0x2001)
            def handle_message(author: str, message: str):
                print(f"{author}: {message}")
        """
        def decorator(handler):
            wrapper = _create_unpacking_handler(handler, is_server_handler=False)
            self._client.register_op_handler(opcode, wrapper)
            return handler
        return decorator

    def default_payload_handler(self, handler):
        """
        Decorator for the default handler, with auto-unpacking based on type hints.
        """
        wrapper = _create_unpacking_handler(handler, is_server_handler=False)
        self._client.set_default_payload_handler(wrapper)
        return handler

