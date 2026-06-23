# SPDX-License-Identifier: GPL-2.0
#
# drv_probe — autonomous on-device verification harness for my-driver.ko
#
# Build (Android NDK):
#   cmake -S scripts -B build-probe \
#         -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30
#   cmake --build build-probe -j
#
cmake_minimum_required(VERSION 3.16)

project(drv_probe
    LANGUAGES C
    DESCRIPTION "Autonomous on-device verification harness for my-driver.ko")

if (NOT ANDROID)
    message(FATAL_ERROR "drv_probe is Android-only.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(drv_probe src/drv_probe.c)

target_include_directories(drv_probe
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../driver/include)

target_compile_options(drv_probe
    PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -Os -ffunction-sections -fdata-sections)

target_link_options(drv_probe PRIVATE -Wl,--gc-sections -s)

install(TARGETS drv_probe RUNTIME DESTINATION bin)
