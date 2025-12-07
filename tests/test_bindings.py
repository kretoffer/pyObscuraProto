import sys
import os
import pytest

# Add build directory to path to find the compiled module.
build_dir = os.path.abspath('build')

# We expect the module to be in the root of the build output, or a subdirectory like 'lib'.
# We add both to be safe.
sys.path.insert(0, build_dir)
sys.path.insert(0, os.path.join(build_dir, 'lib'))

try:
    import pyObscuraProto as op
except ImportError:
    pytest.fail(f"Could not import pyObscuraProto. Make sure it's built and check sys.path. Current sys.path includes: '{build_dir}' and '{os.path.join(build_dir, 'lib')}'", pytrace=False)


def test_read_int_uint_and_peek():
    """
    Tests reading integers of various sizes using the generic read_int/read_uint
    functions and verifies peek_next_param_size.
    """
    builder = op.PayloadBuilder(1)

    # Values that will exercise different integer sizes
    val_i8 = -120
    val_u8 = 250
    val_i16 = -32000
    val_u16 = 65000
    val_i32 = -2000000000
    val_u32 = 4000000000
    val_i64 = -9000000000000000000
    val_u64 = 18000000000000000000

    # Add params. pybind11 should pick the smallest fitting C++ overload.
    builder.add_param(val_i8)   # Stored as int8_t (1 byte)
    builder.add_param(val_u8)   # Stored as uint8_t (1 byte)
    builder.add_param(val_i16)  # Stored as int16_t (2 bytes)
    builder.add_param(val_u16)  # Stored as uint16_t (2 bytes)
    builder.add_param(val_i32)  # Stored as int32_t (4 bytes)
    builder.add_param(val_u32)  # Stored as uint32_t (4 bytes)
    builder.add_param(val_i64)  # Stored as int64_t (8 bytes)
    builder.add_param(val_u64)  # Stored as uint64_t (8 bytes)

    payload = builder.build()
    reader = op.PayloadReader(payload)

    # Read and verify in order, checking the size before each read.
    assert reader.peek_next_param_size() == 1
    assert reader.read_int() == val_i8

    assert reader.peek_next_param_size() == 1
    assert reader.read_uint() == val_u8

    assert reader.peek_next_param_size() == 2
    assert reader.read_int() == val_i16

    assert reader.peek_next_param_size() == 2
    assert reader.read_uint() == val_u16

    assert reader.peek_next_param_size() == 4
    assert reader.read_int() == val_i32

    assert reader.peek_next_param_size() == 4
    assert reader.read_uint() == val_u32

    assert reader.peek_next_param_size() == 8
    assert reader.read_int() == val_i64

    assert reader.peek_next_param_size() == 8
    assert reader.read_uint() == val_u64

    # Ensure there are no more parameters
    assert not reader.has_more()

def test_type_interchangeability():
    """Tests reading a signed parameter as unsigned and vice-versa."""
    # Test reading a parameter added as a uint with read_int()
    builder_i = op.PayloadBuilder(2)
    builder_i.add_param(255)  # Stored as uint8_t
    payload_i = builder_i.build()
    reader_i = op.PayloadReader(payload_i)

    assert reader_i.peek_next_param_size() == 1
    # 255 (unsigned) is -1 in one-byte two's complement representation
    assert reader_i.read_int() == -1

    # Test reading a parameter added as an int with read_uint()
    builder_u = op.PayloadBuilder(3)
    builder_u.add_param(-1)  # Stored as int8_t
    payload_u = builder_u.build()
    reader_u = op.PayloadReader(payload_u)

    assert reader_u.peek_next_param_size() == 1
    # -1 in one-byte two's complement is 255 (unsigned)
    assert reader_u.read_uint() == 255
