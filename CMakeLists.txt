cmake_minimum_required(VERSION 3.16)
project(pq_secure_comm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -fstack-protector-strong)
add_compile_definitions(_DEFAULT_SOURCE _POSIX_C_SOURCE=200809L)

find_package(OpenSSL REQUIRED)

# liboqs is installed to /usr/local by the Dockerfile.
find_library(LIBOQS_LIB oqs REQUIRED HINTS /usr/local/lib)
find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h REQUIRED HINTS /usr/local/include)

include_directories(${LIBOQS_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} src)

set(COMMON_SRC
    src/protocol.c
    src/net.c
    src/session.c
    src/crypto_a.c
    src/crypto_b.c
)

add_executable(alice src/alice.c ${COMMON_SRC})
target_link_libraries(alice PRIVATE ${LIBOQS_LIB} OpenSSL::Crypto OpenSSL::SSL)

add_executable(bob src/bob.c ${COMMON_SRC})
target_link_libraries(bob PRIVATE ${LIBOQS_LIB} OpenSSL::Crypto OpenSSL::SSL)

find_package(Threads REQUIRED)
add_executable(attacker src/attacker.c src/protocol.c src/net.c)
target_link_libraries(attacker PRIVATE OpenSSL::Crypto Threads::Threads)

add_executable(benchmark src/benchmark.c ${COMMON_SRC})
target_link_libraries(benchmark PRIVATE ${LIBOQS_LIB} OpenSSL::Crypto OpenSSL::SSL m)

add_executable(test_protocol src/test_protocol.c src/protocol.c)
target_link_libraries(test_protocol PRIVATE OpenSSL::Crypto)

enable_testing()
add_test(NAME protocol_unit COMMAND test_protocol)
