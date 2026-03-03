cmake_minimum_required (VERSION 3.10)

if(COMMAND cmake_policy)
      cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project (pkcs11 C)

set(VERSION "1.0.0")

set(PKCS11_PROXY_SRCS
    src/proxy/gck-rpc-module.c
    src/common/gck-rpc-message.c
    src/common/gck-rpc-util.c
    src/common/egg-buffer.c
    src/tls/gck-rpc-tls.c
    src/tls/gck-rpc-tls-policy.c
    ext/cjson/cJSON.c)

set(PKCS11_DAEMON_SRCS
    src/daemon/gck-rpc-daemon-standalone.c
    src/common/gck-rpc-dispatch.c
    src/common/gck-rpc-message.c
    src/common/gck-rpc-util.c
    src/common/egg-buffer.c
    src/seccomp/syscall-reporter.c
    src/tls/gck-rpc-tls.c
    src/tls/gck-rpc-tls-policy.c
    ext/cjson/cJSON.c)

# Uncomment for a debug build
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb")

# Search OpenSSL
if (APPLE)
    set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/openssl/lib/pkgconfig/:$ENV{PKG_CONFIG_PATH}")
endif()

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )

    include_directories(${OPENSSL_INCLUDE_DIRS})
    link_directories(${OPENSSL_LIBRARY_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

add_definitions(-Wall -Wextra)

# Project include paths — resolves all #include "foo.h" from the new layout
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR})
add_library(pkcs11-proxy SHARED ${PKCS11_PROXY_SRCS})

# Disable console when building Win32 binary in release mode
if (WIN32)
  if("${CMAKE_BUILD_TYPE}" MATCHES "^Rel.*")
    set(GUI_TYPE WIN32)
  endif()
endif()

add_executable (pkcs11-daemon ${GUI_TYPE} ${PKCS11_DAEMON_SRCS})

set_target_properties(pkcs11-proxy PROPERTIES VERSION 0.1 SOVERSION 0)

if (WIN32)
  include_directories("ext/include")

  add_library(dl STATIC IMPORTED)
  set_property(TARGET dl PROPERTY
               IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/ext/lib/libdl.a)
  target_link_libraries (pkcs11-daemon ws2_32)
  target_link_libraries (pkcs11-proxy ws2_32)
endif (WIN32)

target_link_libraries (pkcs11-proxy pthread ssl crypto)

if (APPLE)
    target_link_libraries (pkcs11-daemon dl pthread ssl crypto)
else()
    target_link_libraries (pkcs11-daemon dl pthread ssl crypto seccomp)
endif()

install_targets (/lib pkcs11-proxy)
install_targets (/bin pkcs11-daemon)

add_custom_command(
   OUTPUT ${CMAKE_SOURCE_DIR}/include/syscall-names.h
   COMMAND ${CMAKE_SOURCE_DIR}/mksyscalls.sh
   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Ensure generated header is built before the daemon
set_source_files_properties(${CMAKE_SOURCE_DIR}/include/syscall-names.h PROPERTIES GENERATED TRUE)
target_sources(pkcs11-daemon PRIVATE ${CMAKE_SOURCE_DIR}/include/syscall-names.h)

