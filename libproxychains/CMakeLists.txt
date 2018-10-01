# Minimum CMake required
cmake_minimum_required(VERSION 3.11)

set(LIB_PROXYCHAINS_SRC
	src/libproxychains.cpp
)

add_library(libproxychains SHARED ${LIB_PROXYCHAINS_SRC})