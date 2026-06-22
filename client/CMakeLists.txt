# SPDX-License-Identifier: GPL-2.0
#
# my-driver-client -- userspace driver for my-driver.ko
#
# Build (Android NDK):
#
#   cmake -S client -B build-android \
#         -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a \
#         -DANDROID_PLATFORM=android-30
#   cmake --build build-android -j
#
# Build (host, for type-checking only -- the reboot() handshake will obviously
# not produce a useful fd on a desktop Linux box):
#
#   cmake -S client -B build && cmake --build build -j
#
cmake_minimum_required(VERSION 3.16)

project(my-driver-client
    LANGUAGES CXX
    DESCRIPTION "Userspace driver for my-driver.ko (Android arm64)")

# ---------------------------------------------------------------------------
# Standard / warnings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ---------------------------------------------------------------------------
# Android NDK awareness
# ---------------------------------------------------------------------------
#
# We don't *require* the NDK -- the code compiles cleanly with any host
# C++17 compiler -- but if the caller forgot to pass a toolchain and the
# ANDROID_NDK env var is set, give them a friendly nudge.
#
if (NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{ANDROID_NDK})
    message(STATUS
        "ANDROID_NDK env var is set ($ENV{ANDROID_NDK}) but no toolchain file "
        "was provided. To cross-compile for Android, re-run with:")
    message(STATUS
        "  -DCMAKE_TOOLCHAIN_FILE=$ENV{ANDROID_NDK}/build/cmake/android.toolchain.cmake "
        "-DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30")
endif()

if (ANDROID)
    message(STATUS "Building for Android (ABI=${ANDROID_ABI}, platform=${ANDROID_PLATFORM})")
endif()

# ---------------------------------------------------------------------------
# Configurable demo defaults
# ---------------------------------------------------------------------------
#
# The Android package and module the demo client offers by default when the
# interactive prompts are left empty. Override these at configure time.
#
set(TARGET_PACKAGE "com.example.game"
    CACHE STRING "Default target package the client will look for")
set(TARGET_MODULE "libUE4.so"
    CACHE STRING "Default module name the client will resolve")

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
add_executable(my-driver-client
    src/Driver.cpp
    src/Main.cpp)

target_include_directories(my-driver-client
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../driver/include)

target_compile_definitions(my-driver-client
    PRIVATE
        HACK_CLIENT_TARGET_PACKAGE="${TARGET_PACKAGE}"
        HACK_CLIENT_TARGET_MODULE="${TARGET_MODULE}")

target_compile_options(my-driver-client
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wno-unused-parameter
        -fno-exceptions
        -fno-rtti)

# Strip release builds aggressively -- this binary is meant to be pushed to
# /data/local/tmp on the device, every kilobyte matters.
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(my-driver-client PRIVATE -Os -ffunction-sections -fdata-sections)
    target_link_options(my-driver-client PRIVATE -Wl,--gc-sections -s)
endif()

install(TARGETS my-driver-client RUNTIME DESTINATION bin)
