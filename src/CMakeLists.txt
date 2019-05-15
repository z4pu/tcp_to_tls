#################################################################
# Variables
#################################################################
set(OPENSSL_RELEASE_TAG "1.1.1b")


# Ensure that our version of OpenSSL is used instead of system installation
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")
message(STATUS "SRC_DIR ${SRC_DIR}")

#################################################################
# Put executables in a directory "bin" in project root
#################################################################
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

#################################################################
# Look for OpenSSL libs
#################################################################
set(OPENSSL_DIR "/opt/openssl/${OPENSSL_RELEASE_TAG}")

find_library(OPENSSL_SSL_CACHE NAMES ssl HINTS ${OPENSSL_DIR}/lib)
find_library(OPENSSL_CRYPTO_CACHE NAMES crypto HINTS ${OPENSSL_DIR}/lib)


#################################################################
# Directories for included headers
#################################################################

include_directories(
    ${OPENSSL_DIR}/include # OpenSSL headers
)
get_property(test_INCLUDE_DIRECTORIES DIRECTORY PROPERTY INCLUDE_DIRECTORIES)
message(STATUS "INCLUDE_DIRECTORIES ${test_INCLUDE_DIRECTORIES}")

#################################################################
# Directories containing libraries for linker
#################################################################

link_directories(
    ${OPENSSL_DIR}/lib # OpenSSL ssl and crypto libraries
)

get_property(test_LINK_DIRECTORIES DIRECTORY PROPERTY LINK_DIRECTORIES)
message(STATUS "LINK_DIRECTORIES ${test_LINK_DIRECTORIES}")

set(openssllibs ${OPENSSL_SSL_CACHE} ${OPENSSL_CRYPTO_CACHE})

#################################################################
# Executables
#################################################################
# server
add_executable(server_tcp
    server_tcp.cpp
    server_tcp_helper.cpp
    common.cpp
)


# client
add_executable(client_tcp
    client_tcp.cpp
    client_tcp_helper.cpp
    common.cpp
)

# server_tls
add_executable(server_tls
    server_tls.cpp
    server_tcp_helper.cpp
    server_tls_helper.cpp
    common_tls.cpp
    common.cpp
)
target_link_libraries(server_tls
    ${openssllibs}
)

# client_tls
add_executable(client_tls
    client_tls.cpp
    client_tls_helper.cpp
    client_tcp_helper.cpp
    common_tls.cpp
    common.cpp
)
target_link_libraries(client_tls
    ${openssllibs}
)
