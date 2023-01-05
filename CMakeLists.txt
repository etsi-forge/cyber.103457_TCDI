# Copyright(c) 2020 etsi103457 ATOS
# Distributed under the BSD-3 License 

cmake_minimum_required(VERSION 3.0)

ENABLE_LANGUAGE(C)

#---------------------------------------------------------------------------------------
# Start etsi103457 project
#---------------------------------------------------------------------------------------
include(cmake/utils.cmake)

etsi103457_extract_version()

project(ETSI103457 VERSION ${ETSI103457_VERSION} LANGUAGES CXX)
message(STATUS "Build ETSI103457 version: ${ETSI103457_VERSION}")

include(GNUInstallDirs)

#---------------------------------------------------------------------------------------
# Set default build to release
#---------------------------------------------------------------------------------------
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose Release or Debug" FORCE)
endif()

#---------------------------------------------------------------------------------------
# Compiler config - Forcing C++11
#---------------------------------------------------------------------------------------
if (NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

set(CMAKE_CXX_EXTENSIONS  OFF)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -Wall -Wunused -Werror -Wpedantic -fexceptions -Wextra -Wstrict-aliasing -Wcast-align -Wmissing-declarations -Wpointer-arith -Wcast-qual -Wzero-as-null-pointer-constant -Wnon-virtual-dtor")

if(CMAKE_SYSTEM_NAME MATCHES "CYGWIN")
	set(CMAKE_CXX_EXTENSIONS ON)
endif()

# build shared option
if(NOT WIN32)
    option(ETSI103457_BUILD_SHARED "Build shared library" OFF)
endif()

find_package(Boost 1.42 REQUIRED)

if(Boost_FOUND)
   include_directories($Boost_INCLUDE_DIRS)
endif()

# Checking for Boost::uuid

set(BOOST_UUID_HEADER "${Boost_INCLUDE_DIRS}/boost/uuid/uuid.hpp")

if(EXISTS "${BOOST_UUID_HEADER}")
else ()
    message(FATAL_ERROR "Boost uuid.hpp header not found in ${Boost_INCLUDE_DIRS}/boost/uuid")
endif()

# example options
option(ETSI103457_BUILD_EXAMPLE "Build example" ${ETSI103457_MASTER_PROJECT})

# testing options
option(ETSI103457_BUILD_TESTS "Build tests" ${ETSI103457_MASTER_PROJECT})

# install options
#option(ETSI103457_INSTALL "Generate the install target" ${ETSI103457_MASTER_PROJECT})

#find_package(Threads REQUIRED)
message(STATUS "Build type: " ${CMAKE_BUILD_TYPE})

#---------------------------------------------------------------------------------------
# Static/Shared library (shared not supported in windows yet)
#---------------------------------------------------------------------------------------
file(GLOB ETSI103457_SRCS ${PROJECT_SOURCE_DIR}/src/*.cpp)

if (ETSI103457_BUILD_SHARED)
    if(WIN32)
        message(FATAL_ERROR "ETSI103457 shared lib is not yet supported under windows")
    endif()
    add_library(etsi103457 SHARED ${ETSI103457_SRCS} ${ETSI103457_ALL_HEADERS})
else()
    add_library(etsi103457 STATIC ${ETSI103457_SRCS} ${ETSI103457_ALL_HEADERS})
endif()

include_directories( BEFORE "${CMAKE_SOURCE_DIR}/../spdlog-git/include")
include_directories( BEFORE "${CMAKE_SOURCE_DIR}/../botan-git/build/include")

target_compile_definitions(etsi103457 PUBLIC ETSI103457_COMPILED_LIB)
target_include_directories(etsi103457 PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

#---------------------------------------------------------------------------------------
# Build doxygen documentation
#---------------------------------------------------------------------------------------
option(BUILD_DOCUMENTATION "Build Documentation" ON)
find_package(Doxygen)
if( DOXYGEN_FOUND )
	set(HAVE_DOT NO)
	set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
	set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

	configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
	message("Doxygen build started")
	add_custom_target( doc_doxygen ALL
		COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
		WORKING_DIRECTORY ${CMAKE_CURENT_BINARY_DIR}
		COMMENT "Generating API documentation with Doxygen"
		VERBATIM )
else (DOXYGEN_FOUND)
	message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)

#---------------------------------------------------------------------------------------
# Build binaries sample
#---------------------------------------------------------------------------------------
if(ETSI103457_BUILD_EXAMPLE)
    message(STATUS "Generating examples")
    add_subdirectory(example)
endif()

#---------------------------------------------------------------------------------------
# Build and run tests
#---------------------------------------------------------------------------------------
if(ETSI103457_BUILD_TESTS)
    message(STATUS "Generating tests")
    enable_testing()
    add_subdirectory(tests)
endif()

#---------------------------------------------------------------------------------------
# Install
#---------------------------------------------------------------------------------------
if (ETSI103457_INSTALL)
    message(STATUS "Generating install")
    set(project_config_in "${CMAKE_CURRENT_LIST_DIR}/cmake/etsi103457Config.cmake.in")
    set(project_config_out "${CMAKE_CURRENT_BINARY_DIR}/etsi103457Config.cmake")
    set(config_targets_file "etsi103457ConfigTargets.cmake")
    set(version_config_file "${CMAKE_CURRENT_BINARY_DIR}/etsi103457ConfigVersion.cmake")
    set(export_dest_dir "${CMAKE_INSTALL_LIBDIR}/cmake/etsi103457")
    set(pkgconfig_install_dir "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    set(pkg_config "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc")

    #---------------------------------------------------------------------------------------
    # Include files
    #---------------------------------------------------------------------------------------
    install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
    install(TARGETS etsi103457 EXPORT etsi103457 DESTINATION "${CMAKE_INSTALL_LIBDIR}")

    #---------------------------------------------------------------------------------------
    # Install pkg-config file
    #---------------------------------------------------------------------------------------
    get_target_property(PKG_CONFIG_DEFINES etsi103457 INTERFACE_COMPILE_DEFINITIONS)
    string(REPLACE ";" " -D" PKG_CONFIG_DEFINES "${PKG_CONFIG_DEFINES}")
    string(CONCAT PKG_CONFIG_DEFINES "-D" "${PKG_CONFIG_DEFINES}")
    configure_file("cmake/${PROJECT_NAME}.pc.in" "${pkg_config}" @ONLY)
    install(FILES "${pkg_config}" DESTINATION "${pkgconfig_install_dir}")

    #---------------------------------------------------------------------------------------
    # Install CMake config files
    #---------------------------------------------------------------------------------------
    install(EXPORT etsi103457
            DESTINATION ${export_dest_dir}
            NAMESPACE TDS::
            FILE ${config_targets_file})

    include(CMakePackageConfigHelpers)
    configure_file("${project_config_in}" "${project_config_out}" @ONLY)

    write_basic_package_version_file("${version_config_file}" COMPATIBILITY SameMajorVersion)
    install(FILES
            "${project_config_out}"
            "${version_config_file}" DESTINATION "${export_dest_dir}")

    #---------------------------------------------------------------------------------------
    # Support creation of installable packages
    #---------------------------------------------------------------------------------------
    include(cmake/etsi103457CPack.cmake)
endif ()

