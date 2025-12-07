#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl_bind.h>

#include <obscuraproto/packet.hpp>

namespace py = pybind11;

PYBIND11_MODULE(pyObscuraProto, m) {
    m.doc() = "Python bindings for the ObscuraProto C++ library";

    // This allows Python code to use the type `ByteVector`, which is a vector of unsigned chars.
    // pybind11 will automatically convert between Python's `bytes` and `std::vector<uint8_t>`.

    
    // Bind the Payload class, which represents the internal data before encryption.
    py::class_<ObscuraProto::Payload>(m, "Payload")
        .def(py::init<>(), "Default constructor")
        .def_readwrite("op_code", &ObscuraProto::Payload::op_code, "The operation code.")
        .def_readwrite("parameters", &ObscuraProto::Payload::parameters, "The raw parameters data.")
        .def("serialize", &ObscuraProto::Payload::serialize, "Serializes the payload into a single byte vector.")
        .def_static("deserialize", &ObscuraProto::Payload::deserialize, "Deserializes a byte vector into a Payload object.");

    // Bind the PayloadBuilder class, a helper to construct a Payload.
    py::class_<ObscuraProto::PayloadBuilder>(m, "PayloadBuilder")
        .def(py::init<ObscuraProto::Payload::OpCode>(), "Constructor that takes an opcode.")
        // The following lines expose all the C++ `add_param` methods to Python.
        // py::overload_cast is used to select the correct C++ method based on the Python argument type.
        .def("add_param", py::overload_cast<const ObscuraProto::byte_vector&>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<const std::string&>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<const char*>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<bool>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int8_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint8_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int16_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint16_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int32_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint32_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<int64_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<uint64_t>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<float>(&ObscuraProto::PayloadBuilder::add_param))
        .def("add_param", py::overload_cast<double>(&ObscuraProto::PayloadBuilder::add_param))
        .def("build", &ObscuraProto::PayloadBuilder::build, "Builds the final Payload object.");

    // Bind the PayloadReader class, a helper to parse parameters from a payload.
    py::class_<ObscuraProto::PayloadReader>(m, "PayloadReader")
        .def(py::init<const ObscuraProto::Payload&>(), "Constructor that takes a payload to read from.")
        .def("has_more", &ObscuraProto::PayloadReader::has_more, "Returns true if there are more parameters to read.")
        .def("peek_next_param_size", &ObscuraProto::PayloadReader::peek_next_param_size, "Returns the size of the next parameter in bytes without advancing the reader.")
        // For the templated `read_param` method, we create explicit functions in Python for each type.
        .def("read_string", &ObscuraProto::PayloadReader::read_param<std::string>, "Reads a string parameter.")
        .def("read_bytes", &ObscuraProto::PayloadReader::read_param<ObscuraProto::byte_vector>, "Reads a bytes parameter.")
        .def("read_bool", &ObscuraProto::PayloadReader::read_param<bool>, "Reads a boolean parameter.")
        .def("read_int", [](ObscuraProto::PayloadReader &self) -> int64_t {
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
        .def("read_uint", [](ObscuraProto::PayloadReader &self) -> uint64_t {
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
        .def("read_float", &ObscuraProto::PayloadReader::read_param<float>, "Reads a 32-bit float.")
        .def("read_double", &ObscuraProto::PayloadReader::read_param<double>, "Reads a 64-bit double.");
}