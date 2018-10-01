# Minimum CMake required
cmake_minimum_required(VERSION 3.11)

set(PROXYCHAINS_SRC
	src/proxychains.cpp
)

add_executable(proxychains ${PROXYCHAINS_SRC})

# need to link ntdll for ntquerysysteminformations
target_link_libraries(proxychains ntdll)