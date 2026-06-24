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
cmake_minimum_required(VERSION 3.16)

project(my-driver-client
    LANGUAGES CXX
    DESCRIPTION "Userspace driver for my-driver.ko (Android arm64)")

if (NOT ANDROID)
    message(FATAL_ERROR
        "my-driver-client is Android-only. Configure with the Android NDK "
        "toolchain, e.g. -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake "
        "-DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30")
endif()

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
message(STATUS "Building for Android (ABI=${ANDROID_ABI}, platform=${ANDROID_PLATFORM})")

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
