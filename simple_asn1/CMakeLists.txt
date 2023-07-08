cmake_minimum_required(VERSION 3.15)
project(SimpleAsn1Lib
	DESCRIPTION "Modern ASN1 DER C++ parser library"
	VERSION 0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost 1.75 REQUIRED)

add_library(SimpleAsn1Lib INTERFACE)

target_include_directories(SimpleAsn1Lib
	INTERFACE include "${Boost_INCLUDE_DIRS}")
