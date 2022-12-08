cmake_minimum_required(VERSION 3.15)

project(SimpleAsn1Tests
	DESCRIPTION "SimpleAsn1 library tests")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost 1.75 REQUIRED)

add_executable(Tests
	main.cpp
	crypto.cpp)
	
target_include_directories(Tests PRIVATE
	"${Boost_INCLUDE_DIRS}"
	"${CMAKE_SOURCE_DIR}")

if (MSVC)
    target_compile_options(Tests PRIVATE /bigobj /W3)
else()
    target_compile_options(Tests PRIVATE -Wall -Wextra -pedantic)
endif()

target_link_libraries(Tests INTERFACE SimpleAsn1Lib PUBLIC gtest_main PUBLIC gmock_main)

add_test(NAME SimpleAsn1Tests COMMAND Tests)
