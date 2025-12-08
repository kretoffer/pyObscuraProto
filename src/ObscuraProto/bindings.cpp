#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/operators.h>
#include <obscuraproto/crypto.hpp>
#include <obscuraproto/handshake_messages.hpp>
#include <obscuraproto/keys.hpp>
#include <obscuraproto/packet.hpp>
#include <obscuraproto/session.hpp>
#include <obscuraproto/version.hpp>
#include <pybind11/functional.h>
#include <map>

namespace py = pybind11;
using namespace ObscuraProto;

class PySessionWrapper {
public:
    PySessionWrapper(Role role, KeyPair key_pair) :
        session(role, std::move(key_pair)) {}

    byte_vector client_initiate_handshake() {
        return session.client_initiate_handshake().serialize();
    }

    byte_vector server_respond_to_handshake(const byte_vector& client_hello_data) {
        auto client_hello = ClientHello::deserialize(client_hello_data);
        auto server_hello = session.server_respond_to_handshake(client_hello);
        if (session.is_handshake_complete()) {
            if (on_handshake_complete) {
                py::gil_scoped_acquire acquire;
                on_handshake_complete();
            }
        }
        return server_hello.serialize();
    }

    void client_finalize_handshake(const byte_vector& server_hello_data) {
        auto server_hello = ServerHello::deserialize(server_hello_data);
        session.client_finalize_handshake(server_hello);
        if (session.is_handshake_complete()) {
            if (on_handshake_complete) {
                py::gil_scoped_acquire acquire;
                on_handshake_complete();
            }
        }
    }

    byte_vector encrypt_payload(const Payload& payload) {
        return session.encrypt_payload(payload);
    }

    Payload decrypt_packet(const byte_vector& packet) {
        auto payload = session.decrypt_packet(packet);

        py::gil_scoped_acquire acquire;
        auto it = op_handlers.find(payload.op_code);
        if (it != op_handlers.end()) {
            it->second(payload);
        } else if (default_payload_handler) {
            default_payload_handler(payload);
        }
        
        return payload;
    }

    bool is_handshake_complete() const {
        return session.is_handshake_complete();
    }

    py::object get_selected_version() const {
        auto version = session.get_selected_version();
        if (version.has_value()) {
            return py::cast(version.value());
        }
        return py::none();
    }

    void set_on_handshake_complete(py::function callback) {
        on_handshake_complete = std::move(callback);
    }

    void register_op_handler(uint16_t op_code, py::function callback) {
        op_handlers[op_code] = std::move(callback);
    }

    void set_default_payload_handler(py::function callback) {
        default_payload_handler = std::move(callback);
    }

private:
    ObscuraProto::Session session;
    py::function on_handshake_complete;
    py::function default_payload_handler;
    std::map<uint16_t, py::function> op_handlers;
};

PYBIND11_MODULE(_obscuraproto, m) {
    m.doc() = "Python bindings for the ObscuraProto C++ library";

    // Version
    m.attr("V1_0") = py::int_(Versions::V1_0);
    m.attr("SUPPORTED_VERSIONS") = py::cast(SUPPORTED_VERSIONS);

    py::class_<VersionNegotiator>(m, "VersionNegotiator")
        .def_static("negotiate", &VersionNegotiator::negotiate);

    // Keys
    py::class_<PublicKey>(m, "PublicKey")
        .def(py::init<>())
        .def_readwrite("data", &PublicKey::data);

    py::class_<PrivateKey>(m, "PrivateKey")
        .def(py::init<>())
        .def_readwrite("data", &PrivateKey::data);

    py::class_<KeyPair>(m, "KeyPair")
        .def(py::init<>())
        .def_readwrite("public_key", &KeyPair::publicKey)
        .def_readwrite("private_key", &KeyPair::privateKey);
    
    py::class_<Signature>(m, "Signature")
        .def(py::init<>())
        .def_readwrite("data", &Signature::data);

    // Handshake Messages
    py::class_<ClientHello>(m, "ClientHello")
        .def(py::init<>())
        .def_readwrite("supported_versions", &ClientHello::supported_versions)
        .def_readwrite("ephemeral_pk", &ClientHello::ephemeral_pk)
        .def("serialize", &ClientHello::serialize)
        .def_static("deserialize", &ClientHello::deserialize);

    py::class_<ServerHello>(m, "ServerHello")
        .def(py::init<>())
        .def_readwrite("selected_version", &ServerHello::selected_version)
        .def_readwrite("ephemeral_pk", &ServerHello::ephemeral_pk)
        .def_readwrite("signature", &ServerHello::signature)
        .def("serialize", &ServerHello::serialize)
        .def_static("deserialize", &ServerHello::deserialize);

    // Crypto
    py::class_<Crypto>(m, "Crypto")
        .def_static("init", &Crypto::init)
        .def_static("generate_kx_keypair", &Crypto::generate_kx_keypair)
        .def_static("generate_sign_keypair", &Crypto::generate_sign_keypair)
        .def_static("sign", &Crypto::sign)
        .def_static("verify", &Crypto::verify)
        .def_static("client_compute_session_keys", &Crypto::client_compute_session_keys)
        .def_static("server_compute_session_keys", &Crypto::server_compute_session_keys)
        .def_static("encrypt", &Crypto::encrypt)
        .def_static("decrypt", &Crypto::decrypt);
    
    py::class_<Crypto::SessionKeys>(m, "SessionKeys")
        .def(py::init<>())
        .def_readwrite("rx", &Crypto::SessionKeys::rx)
        .def_readwrite("tx", &Crypto::SessionKeys::tx);

    // Packet
    py::class_<Payload>(m, "Payload")
        .def(py::init<>(), "Default constructor")
        .def_readwrite("op_code", &Payload::op_code, "The operation code.")
        .def_readwrite("parameters", &Payload::parameters, "The raw parameters data.")
        .def("serialize", &Payload::serialize, "Serializes the payload into a single byte vector.")
        .def_static("deserialize", &Payload::deserialize, "Deserializes a byte vector into a Payload object.");

    py::class_<PayloadBuilder>(m, "PayloadBuilder")
        .def(py::init<Payload::OpCode>(), "Constructor that takes an opcode.")
        .def("add_param", py::overload_cast<const byte_vector&>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<const std::string&>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<const char*>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<bool>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int8_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint8_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int16_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint16_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int32_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint32_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int64_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint64_t>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<float>(&PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<double>(&PayloadBuilder::add_param))
        .def("build", &PayloadBuilder::build, "Builds the final Payload object.");

    py::class_<PayloadReader>(m, "PayloadReader")
        .def(py::init<const Payload&>(), "Constructor that takes a payload to read from.")
        .def("has_more", &PayloadReader::has_more, "Returns true if there are more parameters to read.")
        .def("peek_next_param_size", &PayloadReader::peek_next_param_size, "Returns the size of the next parameter in bytes without advancing the reader.")
        .def("read_string", &PayloadReader::read_param<std::string>, "Reads a string parameter.")
        .def("read_bytes", &PayloadReader::read_param<byte_vector>, "Reads a bytes parameter.")
        .def("read_bool", &PayloadReader::read_param<bool>, "Reads a boolean parameter.")
        .def("read_int", [](PayloadReader &self) -> int64_t {
            size_t size = self.peek_next_param_size();
            switch (size) {
                case 1:
                    return self.read_param<int8_t>();
                case 2:
                    return self.read_param<int16_t>();
                case 4:
                    return self.read_param<int32_t>();
                case 8:
                    return self.read_param<int64_t>();
                default:
                    throw std::runtime_error("Invalid size for a signed integer parameter: " + std::to_string(size));
            }
        }, "Reads a signed integer, determining its size from the packet.")
        .def("read_uint", [](PayloadReader &self) -> uint64_t {
            size_t size = self.peek_next_param_size();
            switch (size) {
                case 1:
                    return self.read_param<uint8_t>();
                case 2:
                    return self.read_param<uint16_t>();
                case 4:
                    return self.read_param<uint32_t>();
                case 8:
                    return self.read_param<uint64_t>();
                default:
                    throw std::runtime_error("Invalid size for an unsigned integer parameter: " + std::to_string(size));
            }
        }, "Reads an unsigned integer, determining its size from the packet.")
        .def("read_float", &PayloadReader::read_param<float>, "Reads a 32-bit float.")
        .def("read_double", &PayloadReader::read_param<double>, "Reads a 64-bit double.");
    
    // Session
    py::enum_<Role>(m, "Role")
        .value("CLIENT", Role::CLIENT)
        .value("SERVER", Role::SERVER)
        .export_values();

    py::class_<PySessionWrapper>(m, "Session")
        .def(py::init<Role, KeyPair>())
        .def("client_initiate_handshake", &PySessionWrapper::client_initiate_handshake)
        .def("server_respond_to_handshake", &PySessionWrapper::server_respond_to_handshake)
        .def("client_finalize_handshake", &PySessionWrapper::client_finalize_handshake)
        .def("encrypt_payload", &PySessionWrapper::encrypt_payload)
        .def("decrypt_packet", &PySessionWrapper::decrypt_packet)
        .def("is_handshake_complete", &PySessionWrapper::is_handshake_complete)
        .def("get_selected_version", &PySessionWrapper::get_selected_version)
        .def("set_on_handshake_complete", &PySessionWrapper::set_on_handshake_complete, "Sets the callback for when the handshake is complete.")
        .def("register_op_handler", &PySessionWrapper::register_op_handler, "Registers a handler for a specific opcode.")
        .def("set_default_payload_handler", &PySessionWrapper::set_default_payload_handler, "Sets the default handler for unhandled opcodes.");
}
