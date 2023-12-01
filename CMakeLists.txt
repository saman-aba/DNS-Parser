cmake_minimum_required(VERSION 3.20)

set(CMAKE_BUILD_TYPE "Debug")
project(DNSParser)

add_executable(DNSParser src/main.c src/parser.h src/parser.c)