#################################################################
# Variables
#################################################################
set(OPENSSL_RELEASE_TAG "1.1.1c")


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
# Include pthreads library
#################################################################

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#################################################################
# Directories containing libraries for linker
#################################################################

if (BUILD_ASAN)
  SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

link_directories(
    ${OPENSSL_DIR}/lib # OpenSSL ssl and crypto libraries
)

get_property(test_LINK_DIRECTORIES DIRECTORY PROPERTY LINK_DIRECTORIES)
message(STATUS "LINK_DIRECTORIES ${test_LINK_DIRECTORIES}")

set(openssllibs ${OPENSSL_SSL_CACHE} ${OPENSSL_CRYPTO_CACHE})

#################################################################
# Executables
#################################################################

# server_udp
add_executable(server_udp
    server_udp.cpp
    server_udp_helper.cpp
    common.cpp
)


# client_udp
add_executable(client_udp
    client_udp.cpp
    client_udp_helper.cpp
    common.cpp
)

# server_dtls
add_executable(server_dtls
    server_dtls.cpp
    server_dtls_helper.cpp
    ck_secrets_vault.c
    common_tls.cpp
    server_udp_helper.cpp
    common.cpp
)
target_link_libraries(server_dtls
    ${openssllibs}
)

# # server_dtls_thread
# add_executable(server_dtls_thread
#     server_dtls_thread.cpp
#     # server_dtls_helper.cpp
#     # ck_secrets_vault.c
#     # common_tls.cpp
#     # server_udp_helper.cpp
#     # common.cpp
# )
# target_link_libraries(server_dtls_thread
#     ${openssllibs}
# )


# client_dtls
add_executable(client_dtls
    client_dtls.cpp
    client_dtls_helper.cpp
    client_tls_helper.cpp
    client_udp_helper.cpp
    common_tls.cpp
    common.cpp
)
target_link_libraries(client_dtls
    ${openssllibs}
)


# server_tcp
add_executable(server_tcp
    server_tcp.cpp
    server_tcp_helper.cpp
    common_tcp.cpp
    common.cpp
)

# server_tcp_thread
add_executable(server_tcp_thread
    server_tcp_thread.cpp
    thread_tcp_helper.cpp
    thread_helper.cpp
    server_tcp_helper.cpp
    common_tcp.cpp
    common.cpp
)
target_link_libraries(server_tcp_thread
    Threads::Threads
)


# client_tcp
add_executable(client_tcp
    client_tcp.cpp
    client_tcp_helper.cpp
    common_tcp.cpp
    common.cpp
)

# server_tls
add_executable(server_tls
    server_tls.cpp
    server_tcp_helper.cpp
    server_tls_helper.cpp
    common_tls.cpp
    common_tcp.cpp
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
    common_tcp.cpp
    common.cpp
)
target_link_libraries(client_tls
    ${openssllibs}
)

# server_sctp_one_to_one
add_executable(server_sctp_one_to_one
    server_sctp_one_to_one.cpp
    server_sctp_helper_one_to_one.cpp
    common_sctp.cpp
    common.cpp
)
target_link_libraries(server_sctp_one_to_one
    sctp
)

# client_sctp_one_to_one
add_executable(client_sctp_one_to_one
    client_sctp_one_to_one.cpp
    client_sctp_helper_one_to_one.cpp
    common_sctp.cpp
    common.cpp
)
target_link_libraries(client_sctp_one_to_one
    sctp
)

# server_sctp_one_to_one_tls
add_executable(server_sctp_one_to_one_tls
    server_sctp_one_to_one_tls.cpp
    server_sctp_helper_one_to_one.cpp
    server_tls_helper.cpp
    common_tls.cpp
    common_sctp.cpp
    common.cpp
)
target_link_libraries(server_sctp_one_to_one_tls
    sctp
    ${openssllibs}
)

# client_sctp_one_to_one_tls
add_executable(client_sctp_one_to_one_tls
    client_sctp_one_to_one_tls.cpp
    client_sctp_helper_one_to_one.cpp
    client_tls_helper.cpp
    common_tls.cpp
    common.cpp
)
target_link_libraries(client_sctp_one_to_one_tls
    sctp
    ${openssllibs}
)

# server_sctp_one_to_many
add_executable(server_sctp_one_to_many
    server_sctp_one_to_many.cpp
    server_sctp_helper_one_to_many.cpp
    common.cpp
)
target_link_libraries(server_sctp_one_to_many
    sctp
)


# client_sctp_one_to_many
add_executable(client_sctp_one_to_many
    client_sctp_one_to_many.cpp
    client_sctp_helper_one_to_many.cpp
    common.cpp
)
target_link_libraries(client_sctp_one_to_many
    sctp
)

# server_sctp_one_to_many_tls
add_executable(server_sctp_one_to_many_tls
    server_sctp_one_to_many_tls.cpp
    server_sctp_helper_one_to_many_tls.cpp
    server_sctp_helper_one_to_many.cpp
    server_dtls_helper.cpp
    ck_secrets_vault.c
    common_tls.cpp
    common.cpp
)
target_link_libraries(server_sctp_one_to_many_tls
    sctp
    ${openssllibs}
)


# client_sctp_one_to_many_tls
add_executable(client_sctp_one_to_many_tls
    client_sctp_one_to_many_tls.cpp
    client_sctp_helper_one_to_many_tls.cpp
    client_sctp_helper_one_to_many.cpp
    client_dtls_helper.cpp
    client_tls_helper.cpp
    common_tls.cpp
    common.cpp
)
target_link_libraries(client_sctp_one_to_many_tls
    sctp
    ${openssllibs}
)
