cmake_minimum_required(VERSION 3.20)

project(DNSParser)



add_executable(DNSParser src/main.c src/parser.h src/parser.c)

target_link_libraries(DNSParser PUBLIC pcap)