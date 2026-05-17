cmake_minimum_required(VERSION 3.20)
project(KernelDetector CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows only
if(WIN32)
    add_executable(KernelDetector
        main.cpp
        ssdt_detector.cpp
        callback_detector.cpp
        driver_scanner.cpp
    )

    target_include_directories(KernelDetector PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

    target_link_libraries(KernelDetector PRIVATE
        ntdll
        advapi32
    )
endif()
