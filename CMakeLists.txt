# Minimum CMake required
cmake_minimum_required(VERSION 3.11)

include(${CMAKE_ROOT}/Modules/ExternalProject.cmake)

# Project

project(proxychains LANGUAGES C CXX VERSION 0.1.0)

# Options

option(PROXYCHAINS_BUILD_TESTS "Build tests" ON)

# Config

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# define cmake dir
set(PROXYCHAINS_CMAKE_DIR "${CMAKE_SOURCE_DIR}/cmake")

if (${PROXYCHAINS_BUILD_TESTS})
    enable_testing()
endif()

# Tree processing

add_subdirectory(proxychains)
add_subdirectory(libproxychains)

# build detours
ExternalProject_Add(Detours 
	GIT_REPOSITORY "https://github.com/Microsoft/Detours.git"
	CONFIGURE_COMMAND ""
	BINARY_DIR	"<prefix>/src/Detours/src"
	BUILD_COMMAND ${CMAKE_COMMAND} -E env DETOURS_TARGET_PROCESSOR=X64 nmake
	INSTALL_COMMAND ""
)

# Summary

message(STATUS "Configuration summary")
message(STATUS "-- Project name                 : ${PROJECT_NAME}")
message(STATUS "-- Project version              : ${PROJECT_VERSION}")
