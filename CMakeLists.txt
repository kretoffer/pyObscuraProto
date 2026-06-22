cmake_minimum_required(VERSION 3.14)
project(ObscuraProto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# On macOS, the fetched libsodium target doesn't properly propagate link info.
# Set linker flags globally so all targets can find -lsodium from Homebrew.
if(APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L/opt/homebrew/lib")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -L/opt/homebrew/lib")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -L/opt/homebrew/lib")
endif()

# Disable ObscuraProto's own tests (they'd need system libsodium too)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

include(FetchContent)

FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG        v2.11.1
)
FetchContent_MakeAvailable(pybind11)

FetchContent_Declare(
    ObscuraProto
    GIT_REPOSITORY https://github.com/kretoffer/ObscuraProto.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(ObscuraProto)

pybind11_add_module(_obscuraproto src/ObscuraProto/bindings.cpp)
target_link_libraries(_obscuraproto PRIVATE obscuraproto)

# Add system libsodium include path for headers like sodium/version.h
if(APPLE)
    find_path(LIBSODIUM_INCLUDE_DIR sodium/version.h
        HINTS /opt/homebrew /usr/local /usr
        PATH_SUFFIXES include
    )
    if(LIBSODIUM_INCLUDE_DIR)
        target_include_directories(obscuraproto PUBLIC "${LIBSODIUM_INCLUDE_DIR}")
        message(STATUS "Using system libsodium include: ${LIBSODIUM_INCLUDE_DIR}")
    endif()
endif()
