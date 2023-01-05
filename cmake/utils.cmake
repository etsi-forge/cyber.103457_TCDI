# Get etsi103457 version from include/version.h and put it in ETSI103457_VERSION
function(etsi103457_extract_version)
	file(READ "${CMAKE_CURRENT_LIST_DIR}/include/version.h" file_contents)
	string(REGEX MATCH "ETSI103457_VER_MAJOR ([0-9]+)" _  "${file_contents}")
	if(NOT CMAKE_MATCH_COUNT EQUAL 1)
        message(FATAL_ERROR "Could not extract major version number from version.h")
	endif()
	set(ver_major ${CMAKE_MATCH_1})

	string(REGEX MATCH "ETSI103457_VER_MINOR ([0-9]+)" _  "${file_contents}")
	if(NOT CMAKE_MATCH_COUNT EQUAL 1)
        message(FATAL_ERROR "Could not extract minor version number from version.h")
	endif()

	set(ver_minor ${CMAKE_MATCH_1})
	string(REGEX MATCH "ETSI103457_VER_PATCH ([0-9]+)" _  "${file_contents}")
	if(NOT CMAKE_MATCH_COUNT EQUAL 1)
        message(FATAL_ERROR "Could not extract patch version number from version.h")
	endif()
	set(ver_patch ${CMAKE_MATCH_1})

    set(ETSI103457_VERSION_MAJOR ${ver_major} PARENT_SCOPE)
	set (ETSI103457_VERSION "${ver_major}.${ver_minor}.${ver_patch}" PARENT_SCOPE)
endfunction()


