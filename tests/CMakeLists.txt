# Copyright(c) 2019 ATOS & ETSI
# Distributed under the BSD-3 License 

cmake_minimum_required(VERSION 3.1)
project(etsi103457_tests CXX)

include(../cmake/utils.cmake)


#---------------------------------------------------------------------------------------
# Example of using pre-compiled library
#---------------------------------------------------------------------------------------

set(TEST_SRC tests.cpp ConnectionCommands.cpp ObjectCommands.cpp CryptoCommands.cpp ArchiveCommands.cpp StorageCommands.cpp SessionCommands.cpp)

set(CATCH_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/../Catch2-git/single_include/catch2)
add_library(Catch INTERFACE)
target_include_directories(Catch INTERFACE ${CATCH_INCLUDE_DIR})

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
add_executable(tests ${TEST_SRC})
target_link_libraries(tests PRIVATE etsi103457 botan-2 spdlog Catch boost_system boost_filesystem)


set( UNIT_TEST "tests")
add_custom_command(
     TARGET ${UNIT_TEST}
     COMMENT "Running tests"
     POST_BUILD 
     COMMAND ${UNIT_TEST}
)
