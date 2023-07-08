cmake_minimum_required(VERSION 3.15)

project(SimpleAsn1
	DESCRIPTION "Modern ASN1 DER C++ parser library")

if (NOT DEFINED SIMPLE_ASN1_ROOT_PROJECT)
	set(SIMPLE_ASN1_ROOT_PROJECT OFF)
	if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
		set(SIMPLE_ASN1_ROOT_PROJECT ON)
	endif()
endif()

set(SIMPLE_ASN1_BUILD_TESTS ${SIMPLE_ASN1_ROOT_PROJECT} CACHE BOOL "Build tests")
set(SIMPLE_ASN1_BUILD_EXAMPLES ${SIMPLE_ASN1_ROOT_PROJECT} CACHE BOOL "Build examples")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(simple_asn1)

if (SIMPLE_ASN1_BUILD_EXAMPLES)
	add_subdirectory(x509_reader)
endif()

if (SIMPLE_ASN1_BUILD_TESTS)
	enable_testing()
	set(BUILD_GMOCK ON CACHE INTERNAL "" FORCE)
	set(INSTALL_GTEST OFF CACHE INTERNAL "" FORCE)
	add_subdirectory(googletest)
	include(GoogleTest)
	include(CTest)
	add_subdirectory(simple_asn1_tests)
endif()
