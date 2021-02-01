cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(atc_mi_collector)

set(CMAKE_CXX_STANDARD 17)

find_package(prometheus-cpp CONFIG REQUIRED)

add_executable(atc_mi_collector atc_mi_collector.cc)
target_link_libraries(atc_mi_collector PRIVATE prometheus-cpp::pull bluetooth)
