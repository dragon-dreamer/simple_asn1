cmake_minimum_required(VERSION 3.15)

project(X509Reader
	DESCRIPTION "Simple X509 reader using SimpleAsn1")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(Boost 1.75 REQUIRED)

add_executable(X509Reader main.cpp)

if (MSVC)
    target_compile_options(X509Reader PRIVATE /bigobj /W3
		/D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
else()
    target_compile_options(X509Reader PRIVATE -Wall -Wextra -pedantic)
endif()

target_include_directories(X509Reader PRIVATE
	"${Boost_INCLUDE_DIRS}"
	"${CMAKE_SOURCE_DIR}")
target_link_libraries(X509Reader INTERFACE SimpleAsn1Lib)
