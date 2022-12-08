cmake_minimum_required(VERSION 3.15)

project(SimpleAsn1
	DESCRIPTION "Modern ASN1 DER C++ parser library")

set(BUILD_TESTS 1 CACHE BOOL "Build tests")
set(BUILD_EXAMPLES 1 CACHE BOOL "Build examples")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(simple_asn1)

if(BUILD_EXAMPLES)
	add_subdirectory(x509_reader)
endif()

if(BUILD_TESTS)
	add_subdirectory(googletest)
	enable_testing()
	add_subdirectory(simple_asn1_tests)
endif()
