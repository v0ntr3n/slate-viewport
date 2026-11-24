cmake_minimum_required(VERSION 3.20)

project(gclient-win32
    VERSION 1.0.0
    DESCRIPTION "Win32 Client Native Win32 x86 Port (Cocos2d-x 2.2.6 + Lua)"
    LANGUAGES C CXX
)

# ==============================================================================
# 1. Toolchain & Architecture Enforcement (MSVC Win32 x86 + /LARGEADDRESSAWARE)
# ==============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(GCLIENT_ENFORCE_WIN32_X86 "Require 32-bit x86 target on MSVC" ON)
option(GCLIENT_ENABLE_LUAPROFILER "Register optional luaopen_luaprofiler binding" OFF)
option(GCLIENT_BUILD_TESTS "Build unit and integration test targets" OFF)
option(GCLIENT_ASSUME_PATCHED_COCOS2DX
    "Define GCLIENT_CCFILEUTILS_HAS_SET_DECRYPT (expects tools/patch_cocos2dx.py applied)" ON)

if(WIN32 AND MSVC)
    if(GCLIENT_ENFORCE_WIN32_X86 AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(FATAL_ERROR
            "Win32 Client targets Win32 x86 (32-bit) for Cocos2d-x 2.2.6 compatibility. "
            "Configure with '-A Win32' (or pass -DGCLIENT_ENFORCE_WIN32_X86=OFF to override)."
        )
    endif()
endif()

# ==============================================================================
# 2. External Cocos2d-x 2.2.6 (Patched via tools/patch_cocos2dx.py)
# ==============================================================================
if(DEFINED COCOS2DX_ROOT AND NOT DEFINED GCLIENT_COCOS2DX_ROOT)
    set(GCLIENT_COCOS2DX_ROOT "${COCOS2DX_ROOT}")
endif()
set(GCLIENT_COCOS2DX_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/external/cocos2d-x-2.2.6"
    CACHE PATH "Path to Cocos2d-x 2.2.6 source tree")

set(GCLIENT_COCOS2DX_LIB_DIR "${GCLIENT_COCOS2DX_ROOT}/Debug.win32"
    CACHE PATH "Path to prebuilt Cocos2d-x 2.2.6 Win32 import libraries (optional)")

option(GCLIENT_COCOS2DX_BUILD_FROM_SOURCE
    "Add Cocos2d-x 2.2.6 via add_subdirectory instead of linking prebuilt Win32 libs" OFF)

if(NOT EXISTS "${GCLIENT_COCOS2DX_ROOT}")
    message(WARNING
        "Cocos2d-x 2.2.6 directory not found at '${GCLIENT_COCOS2DX_ROOT}'. "
        "Place the Cocos2d-x 2.2.6 tree there and run 'python tools/patch_cocos2dx.py external/cocos2d-x-2.2.6' before building."
    )
elseif(EXISTS "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/CCFileUtils.h")
    file(READ "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/CCFileUtils.h" _gclient_ccfileutils_hdr)
    if(NOT _gclient_ccfileutils_hdr MATCHES "GCLIENT_BT_DECRYPT_HOOK")
        message(WARNING
            "CCFileUtils.h at '${GCLIENT_COCOS2DX_ROOT}' does not contain GCLIENT_BT_DECRYPT_HOOK yet. "
            "Run 'python tools/patch_cocos2dx.py \"${GCLIENT_COCOS2DX_ROOT}\"' before compiling."
        )
    endif()
    unset(_gclient_ccfileutils_hdr)
endif()

# Overlay include directories placed BEFORE Cocos2d-x headers.
set(GCLIENT_OVERLAY_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/assets/overlay")
    list(APPEND GCLIENT_OVERLAY_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/src/assets/overlay")
endif()

set(GCLIENT_COCOS2DX_INCLUDE_DIRS
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/include"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/kazmath/include"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/win32"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/third_party/win32"
    "${GCLIENT_COCOS2DX_ROOT}/cocos2dx/platform/third_party/win32/OGLES"
    "${GCLIENT_COCOS2DX_ROOT}/CocosDenshion/include"
    "${GCLIENT_COCOS2DX_ROOT}/extensions"
    "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/cocos2dx_support"
    "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/lua"
    "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/tolua"
    "${GCLIENT_COCOS2DX_ROOT}/external"
)

add_library(gclient_cocos2dx_interface INTERFACE)
target_include_directories(gclient_cocos2dx_interface INTERFACE
    ${GCLIENT_OVERLAY_INCLUDE_DIRS}
    ${GCLIENT_COCOS2DX_INCLUDE_DIRS}
)
target_compile_definitions(gclient_cocos2dx_interface INTERFACE
    $<$<BOOL:${GCLIENT_ASSUME_PATCHED_COCOS2DX}>:GCLIENT_CCFILEUTILS_HAS_SET_DECRYPT=1>
)

if(GCLIENT_COCOS2DX_BUILD_FROM_SOURCE AND EXISTS "${GCLIENT_COCOS2DX_ROOT}/CMakeLists.txt")
    add_subdirectory("${GCLIENT_COCOS2DX_ROOT}" "${CMAKE_BINARY_DIR}/external/cocos2d-x-2.2.6" EXCLUDE_FROM_ALL)
    target_link_libraries(gclient_cocos2dx_interface INTERFACE
        cocos2d
        CocosDenshion
        extensions
        lua
    )
else()
    target_link_directories(gclient_cocos2dx_interface INTERFACE
        "${GCLIENT_COCOS2DX_LIB_DIR}"
        "${GCLIENT_COCOS2DX_ROOT}/scripting/lua/luajit/win32"
    )
    target_link_libraries(gclient_cocos2dx_interface INTERFACE
        libcocos2d
        libCocosDenshion
        libExtensions
        liblua
        lua51
    )
endif()

# ==============================================================================
# 3. Third-Party Dependencies (vcpkg / CMake Package Registry)
# ==============================================================================
find_package(SQLite3 REQUIRED)
find_package(Protobuf REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# Resolve protoc executable reliably across vcpkg and system installs
if(TARGET protobuf::protoc)
    set(GCLIENT_PROTOC_EXECUTABLE $<TARGET_FILE:protobuf::protoc>)
elseif(DEFINED Protobuf_PROTOC_EXECUTABLE AND EXISTS "${Protobuf_PROTOC_EXECUTABLE}")
    set(GCLIENT_PROTOC_EXECUTABLE "${Protobuf_PROTOC_EXECUTABLE}")
else()
    find_program(GCLIENT_PROTOC_EXECUTABLE NAMES protoc REQUIRED)
endif()

# ==============================================================================
# 4. Protobuf Code Generation (CSGUI.proto, CSScene.proto, db.proto)
# ==============================================================================
set(GCLIENT_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(GCLIENT_PROTO_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/proto")
file(MAKE_DIRECTORY "${GCLIENT_PROTO_GEN_DIR}")

set(GCLIENT_PROTO_FILES
    "${GCLIENT_PROTO_DIR}/CSGUI.proto"
    "${GCLIENT_PROTO_DIR}/CSScene.proto"
    "${GCLIENT_PROTO_DIR}/db.proto"
)

set(GCLIENT_PROTO_SRCS "")
set(GCLIENT_PROTO_HDRS "")

foreach(proto_file IN LISTS GCLIENT_PROTO_FILES)
    get_filename_component(proto_name "${proto_file}" NAME_WE)
    set(gen_cc "${GCLIENT_PROTO_GEN_DIR}/${proto_name}.pb.cc")
    set(gen_h  "${GCLIENT_PROTO_GEN_DIR}/${proto_name}.pb.h")

    add_custom_command(
        OUTPUT "${gen_cc}" "${gen_h}"
        COMMAND "${GCLIENT_PROTOC_EXECUTABLE}"
            "--cpp_out=${GCLIENT_PROTO_GEN_DIR}"
            "-I${GCLIENT_PROTO_DIR}"
            "${proto_file}"
        DEPENDS "${proto_file}"
        COMMENT "Generating C++ protobuf sources from proto/${proto_name}.proto"
        VERBATIM
    )

    list(APPEND GCLIENT_PROTO_SRCS "${gen_cc}")
    list(APPEND GCLIENT_PROTO_HDRS "${gen_h}")
endforeach()

add_library(gclient_proto STATIC ${GCLIENT_PROTO_SRCS} ${GCLIENT_PROTO_HDRS})
target_include_directories(gclient_proto PUBLIC "${GCLIENT_PROTO_GEN_DIR}")
target_link_libraries(gclient_proto PUBLIC protobuf::libprotobuf)
if(MSVC)
    # Suppress third-party warnings inside generated protobuf code
    target_compile_options(gclient_proto PRIVATE /W0)
endif()

# ==============================================================================
# 5. Common Compiler & Platform Settings
# ==============================================================================
add_library(gclient_build_options INTERFACE)
target_compile_features(gclient_build_options INTERFACE cxx_std_17)
target_compile_definitions(gclient_build_options INTERFACE
    WIN32
    _WINDOWS
    WIN32_LEAN_AND_MEAN
    _HAS_AUTO_PTR_ETC=1
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
    CC_TARGET_OS_WIN32
    GCLIENT_USE_COCOS2DX=1
    GCLIENT_ENABLE_COCOS2DX=1
    $<$<BOOL:${GCLIENT_ASSUME_PATCHED_COCOS2DX}>:GCLIENT_CCFILEUTILS_HAS_SET_DECRYPT=1>
    $<$<BOOL:${GCLIENT_ENABLE_LUAPROFILER}>:GCLIENT_ENABLE_LUAPROFILER=1>
)

if(MSVC)
    target_compile_options(gclient_build_options INTERFACE
        /W4
        /MP
        /utf-8
        /EHsc
        /permissive-
        /Zc:__cplusplus
        $<$<CONFIG:Release>:/Zi /O2 /Oi /GL>
    )
    target_link_options(gclient_build_options INTERFACE
        /LARGEADDRESSAWARE
        $<$<CONFIG:Release>:/DEBUG /LTCG /OPT:REF /OPT:ICF>
    )
endif()

# ==============================================================================
# 6. Modular src/ Subsystems
#    Modules: diagnostics, assets, net, bindings, platform, update, ui
# ==============================================================================

# --- 6a. Diagnostics Module (CrashAndTelemetry) ---
add_library(gclient_diagnostics STATIC
    src/diagnostics/CrashAndTelemetry.h
    src/diagnostics/CrashAndTelemetry.cpp
)
target_include_directories(gclient_diagnostics PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(gclient_diagnostics
    PUBLIC
        gclient_build_options
        gclient_cocos2dx_interface
    PRIVATE
        dbghelp
        psapi
)

# --- 6b. Helper for sibling overlay modules (assets, net, bindings, platform, update, ui) ---
function(gclient_add_module MODULE_NAME SUBDIR)
    set(mod_dir "${CMAKE_CURRENT_SOURCE_DIR}/src/${SUBDIR}")
    if(EXISTS "${mod_dir}/CMakeLists.txt")
        add_subdirectory("${mod_dir}")
        return()
    endif()

    file(GLOB_RECURSE mod_sources CONFIGURE_DEPENDS
        "${mod_dir}/*.cpp"
        "${mod_dir}/*.cc"
        "${mod_dir}/*.c"
        "${mod_dir}/*.h"
        "${mod_dir}/*.hpp"
    )

    set(has_compilable_src FALSE)
    foreach(f IN LISTS mod_sources)
        if(f MATCHES "\\.(cpp|cc|c)$")
            set(has_compilable_src TRUE)
            break()
        endif()
    endforeach()

    if(has_compilable_src)
        add_library(${MODULE_NAME} STATIC ${mod_sources})
        target_include_directories(${MODULE_NAME} PUBLIC
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${mod_dir}"
        )
        target_link_libraries(${MODULE_NAME} PUBLIC
            gclient_build_options
            gclient_cocos2dx_interface
            gclient_diagnostics
            gclient_proto
            SQLite::SQLite3
            CURL::libcurl
            OpenSSL::SSL
            OpenSSL::Crypto
            ZLIB::ZLIB
        )
        if(WIN32)
            target_link_libraries(${MODULE_NAME} PUBLIC
                ws2_32
                bcrypt
                crypt32
                user32
                gdi32
                advapi32
            )
        endif()
    else()
        add_library(${MODULE_NAME} INTERFACE)
        target_include_directories(${MODULE_NAME} INTERFACE
            "${CMAKE_CURRENT_SOURCE_DIR}/src"
            "${mod_dir}"
        )
    endif()
endfunction()

gclient_add_module(gclient_assets   assets)
gclient_add_module(gclient_net      net)
gclient_add_module(gclient_bindings bindings)
gclient_add_module(gclient_platform platform)
gclient_add_module(gclient_update   update)
gclient_add_module(gclient_ui       ui)

# ==============================================================================
# 7. Main Win32 Executable Target
# ==============================================================================
add_executable(gclient WIN32
    src/main.cpp
    src/AppDelegate.h
    src/AppDelegate.cpp
)

set_target_properties(gclient PROPERTIES
    OUTPUT_NAME "GCLIENT"
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>"
)

target_include_directories(gclient PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(gclient PRIVATE
    gclient_build_options
    gclient_cocos2dx_interface
    gclient_diagnostics
    gclient_assets
    gclient_net
    gclient_bindings
    gclient_platform
    gclient_update
    gclient_ui
    gclient_proto
    SQLite::SQLite3
    protobuf::libprotobuf
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ws2_32
    bcrypt
    crypt32
    user32
    gdi32
    advapi32
    dbghelp
    psapi
    shell32
    comdlg32
    shlwapi
    ole32
    winmm
    opengl32
)

if(MSVC)
    target_link_options(gclient PRIVATE
        /SUBSYSTEM:WINDOWS
        /LARGEADDRESSAWARE
    )
endif()
