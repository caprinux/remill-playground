cmake_minimum_required(VERSION 3.15)
project(remill-workdir CXX)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(GFLAGS_USE_TARGET_NAMESPACE ON)

find_package(LLVM-Wrapper REQUIRED)
find_package(remill REQUIRED)

add_executable(remill-workdir main.cpp)
target_link_libraries(remill-workdir PRIVATE LLVM-Wrapper remill)
