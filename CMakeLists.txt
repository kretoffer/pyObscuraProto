cmake_minimum_required(VERSION 3.14)
project(ObscuraProto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

include(FetchContent)

FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG        v2.11.1
)
FetchContent_MakeAvailable(pybind11)

# Find libsodium before fetching ObscuraProto — the upstream CMake uses
# LIBSODIUM_INCLUDE_DIR / LIBSODIUM_LIBRARY.  By caching them here first,
# the upstream's find_path / find_library will skip searching.
# On Windows with vcpkg toolchain, CMAKE_FIND_ROOT_PATH is set to the vcpkg
# install dir, so find_* without platform-specific HINTS locates libsodium.
find_path(LIBSODIUM_INCLUDE_DIR NAMES sodium.h)
find_library(LIBSODIUM_LIBRARY NAMES sodium libsodium)

if(LIBSODIUM_INCLUDE_DIR AND LIBSODIUM_LIBRARY)
    set(LIBSODIUM_INCLUDE_DIR "${LIBSODIUM_INCLUDE_DIR}" CACHE PATH "" FORCE)
    set(LIBSODIUM_LIBRARY "${LIBSODIUM_LIBRARY}" CACHE FILEPATH "" FORCE)
    message(STATUS "Found libsodium: ${LIBSODIUM_LIBRARY}")
else()
    message(WARNING "libsodium not found; ObscuraProto must find it independently")
endif()

FetchContent_Declare(
    ObscuraProto
    GIT_REPOSITORY https://github.com/ObscuraEcosystem/ObscuraProto.git
    GIT_TAG        v1.0
)
FetchContent_MakeAvailable(ObscuraProto)

# Propagate libsodium to obscuraproto target
if(LIBSODIUM_LIBRARY)
    target_link_libraries(obscuraproto PUBLIC "${LIBSODIUM_LIBRARY}")
endif()
if(LIBSODIUM_INCLUDE_DIR)
    target_include_directories(obscuraproto PUBLIC "${LIBSODIUM_INCLUDE_DIR}")
endif()

pybind11_add_module(_obscuraproto src/ObscuraProto/bindings.cpp)
target_link_libraries(_obscuraproto PRIVATE obscuraproto)
