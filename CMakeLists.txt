cmake_minimum_required(VERSION 3.16)
project(NetSentry VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

add_library(netsentry_core
    src/analyzer.cpp
    src/packet_parser.cpp
    src/pcap_reader.cpp
    src/report_writer.cpp
)
target_include_directories(netsentry_core PUBLIC include)
target_link_libraries(netsentry_core PUBLIC Threads::Threads)

if(MSVC)
    target_compile_options(netsentry_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(netsentry_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(netsentry src/main.cpp)
target_link_libraries(netsentry PRIVATE netsentry_core)
target_compile_definitions(netsentry PRIVATE NETSENTRY_VERSION="${PROJECT_VERSION}")

include(CTest)
if(BUILD_TESTING)
    add_executable(netsentry_tests tests/test_main.cpp)
    target_link_libraries(netsentry_tests PRIVATE netsentry_core)
    add_test(NAME netsentry_tests COMMAND netsentry_tests)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME netsentry_cli_integration
            COMMAND Python3::Interpreter
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration_test.py
                $<TARGET_FILE:netsentry>
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_test_pcap.py
                ${CMAKE_CURRENT_BINARY_DIR}
        )
    endif()
endif()
