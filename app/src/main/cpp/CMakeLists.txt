cmake_minimum_required(VERSION 3.10.2)
project("dirtysepolicy")

set(CMAKE_CXX_STANDARD 17)

add_library(
    dirtysepolicy
    SHARED
    dirtysepolicy.cpp
)

find_library(log-lib log)

target_link_libraries(
    dirtysepolicy
    ${log-lib}
)