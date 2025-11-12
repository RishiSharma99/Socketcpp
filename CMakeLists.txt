cmake_minimum_required(VERSION 3.28)

project(SocketCPP LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(cmake/CompilerWarnings.cmake)

add_executable(main)

target_compile_features(main PUBLIC cxx_std_23)
target_include_directories(main BEFORE PRIVATE src)

set_project_warnings(main)

target_sources(main
PUBLIC
    FILE_SET modules TYPE CXX_MODULES
    BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/src"

    FILES
        src/socket.cppm
PRIVATE

   src/main.cpp
)

