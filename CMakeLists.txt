cmake_minimum_required(VERSION 3.14)
project(ObscuraProto)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# This is a modern CMake approach to fetching dependencies
include(FetchContent)

# Fetch pybind11 from its repository
FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG        v2.11.1 # Using a recent, stable version
)
# Make pybind11 available to the project
FetchContent_MakeAvailable(pybind11)

# Fetch ObscuraProto from its repository
FetchContent_Declare(
    ObscuraProto
    GIT_REPOSITORY https://github.com/kretoffer/ObscuraProto.git
    GIT_TAG        main # Using the main branch
)
# Make ObscuraProto available. This will add its targets to our build.
FetchContent_MakeAvailable(ObscuraProto)

# Create the Python module using the pybind11 helper function.
# This module will be named 'pyObscuraProto' and will be built from our bindings file.
pybind11_add_module(_obscuraproto src/ObscuraProto/bindings.cpp)

# Link our Python module against the ObscuraProto library.
# This makes all the functions and classes from ObscuraProto available to our binding code.
target_link_libraries(_obscuraproto PRIVATE obscuraproto)
