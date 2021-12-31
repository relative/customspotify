cmake_minimum_required(VERSION 3.13) # target_link_options

project(hook)

set(CMAKE_CXX_STANDARD 17)

# eek
file(GLOB hook_CEF
        "src/include/*.h")

# vcpkg is unable to use different target triplets in cmake subprojects/dirs
add_subdirectory(minhook)

include_directories(src/)

add_library(hook SHARED
        src/main.cpp
         src/ntdll.h src/display.h src/hook/hook.cpp src/hook/hook.h src/hook/renderer.cpp src/hook/renderer.h src/hook/browser.cpp src/hook/browser.h
        ${hook_CEF})

if(MSVC)
    if(CMAKE_BUILD_TYPE MATCHES Debug)
        #target_link_options(hook PUBLIC /BASE:0x6F000000 /FIXED /DYNAMICBASE:NO)
        target_link_options(hook PUBLIC /DYNAMICBASE)
    else()
        target_link_options(hook PUBLIC /DYNAMICBASE)
    endif()
endif()
target_link_libraries(hook PRIVATE minhook)