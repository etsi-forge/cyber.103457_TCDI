# Copyright(c) 2019 ATOS & ETSI
# Distributed under the BSD-3 License 

cmake_minimum_required(VERSION 3.1)
project(etsi103457_tests CXX)

include(../cmake/utils.cmake)

#---------------------------------------------------------------------------------------
# Example of using pre-compiled library
#---------------------------------------------------------------------------------------

set(TLS_SERVER main_tls_server.cpp cli.cpp cli_rng.cpp sandbox.cpp tls_server.cpp)


add_library(botan-2 SHARED IMPORTED)
set_target_properties(botan-2 PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../botan-git/libbotan-2.so"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../botan-git/build/include"
)

add_library(spdlog STATIC IMPORTED)
set_target_properties(spdlog PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/../spdlog-git/build/libspdlog.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/../spdlog-git/include"
)

add_executable(tls_server ${TLS_SERVER})
target_link_libraries(tls_server PRIVATE etsi103457 botan-2 spdlog boost_system boost_filesystem)

