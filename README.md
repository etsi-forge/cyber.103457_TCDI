# ETSI TS103457 "Trusted Cross-Domain Interface: Interface to offload sensitive functions to a trusted domain"

Example implementation and demonstrator

This software is made of a library providing connection and session with trust management, message encoding and related functionnal examples done at server side (MTD).

## Dependencies installation

This description is for debian linux distribution.

Build tool packages :
 - g++
 - cmake

For botan library
  - libboost-all-dev
  - lzma-dev
  - liblzma-dev
  - libbz2-dev
  - libssl-dev
  - xv-utils

For documentation :
  - doxygen
  - graphviz

For client GUI :
  - python3
  - python3-pip
  - python3-tk

Libraries from github are required:
  - botan (crypto library): https://github.com/randombit/botan (version 2.17.3)
  - spdlog (logging library): https://github.com/gabime/spdlog
  - google catch2 (unit testing framework): https://github.com/catchorg/Catch2 (version v2.13.4)


### botan build
  - from source project root
  - `./configure.py --with-boost --with-openssl --with-bzip2 --with-lzma --with-zlib`
  - `make`

### spdlog build
  - `mkdir build && cd buid && cmake ..`
  - `make`

The location of the dependency libraries is defined in main CMakeLists.txt
Default locations are ../botan-git, ../spdlog-git and ../Catch2-git

## Project build

The library is C++ coded and uses cmake toolchain for building
The build generates libetsi103457 library, example MTD server, doxygen documentation 
and unit testing binaries.

These build options can be used with cmake:

  - `-DETSI103457_BUILD_TESTS=1`
  to enable unit testing

  - `-DETSI103457_BUILD_EXAMPLE=1`
  to build the server

## Code description

Every function from the TS has a corresponding class derived from a TDS_Commands base class.
The concept elements defined in TS are directly mapped into classes in the library :
 - TD_Message is the TTLV encoded command/response content
 - TD_Object is the generic object handled by the MTD
 - TD_Container is a MTD container

TD_TLLVTools is a static class used for coding/decoding all the types defined in the standard
TD_Connection is in charge of the protocol connection handling over and except the transport layer.
TD_Session_Manager is for the lifecycle management of the objects inside the sessions.

## Demonstrator description

The project goal is to illustrate the interactions and processings for the two domains, MTD, the more trusted domain and LTD, the lesser one. It exhibits a client/server architecture where the client in LTD offload some sensible processings
to an MTD server.

A TLS transport layer is used as recommended in standard. Demo keys and certificates are given in pki directory.

The client is a pure python implementation with a portable Tk GUI.

## Demonstrator Usage

From example directory
 - The client can be run with `python3 etsi103457-gui.py`
 - The server can be run with `./tls_server.sh` wrapper script


## Demonstrator limitations
 - The Demonstrator server is synchronous and will only accept a single client connection at a time
 - DB access has not been implemented in this Demonstrator, therefore (key/value) base type are not supported
 - TD_OpenConnection : 
      - parameters are not used
 - TD_TrustRenewal :
      - Trust is automatically checked every 240 seconds from the client. In order to demonstrate the loss of trust, BAD_CN is passed to the server as CN value when the Trusted Value checkbox is unticked in the client
 - TD_Object : 
      - Allthough Objects are stored as RAW data (bytestrings), Object values should be entered as string for logging purpose
 - TD_GetRandom :
      - SizeInBytes shall be lower than XX due to libbotan implementation
 - Archive and Storage are stored as files by default in /tmp and are prefixed by ARC and STO for demonstration purposes
      - Files content is stored as human readable content. The Storage name is stored as a string when applying, Object_Id are stored as human readable uuid, and values are Base64 encoded





