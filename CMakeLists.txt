cmake_minimum_required(VERSION 3.13)

# vcpkg (only Windows)
if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(VCPKG_TARGET_TRIPLET "x86-windows" CACHE STRING "VCPKG_TARGET_TRIPLET" FORCE)
    message(STATUS "Target triplet for debug is " ${VCPKG_TARGET_TRIPLET})
else()
    set(VCPKG_TARGET_TRIPLET "x86-windows" CACHE STRING "VCPKG_TARGET_TRIPLET" FORCE)
    message(STATUS "Target triplet for release is " ${VCPKG_TARGET_TRIPLET})
endif()

# CMAKE_TOOLCHAIN_FILE MUST be defined before project
# alternatively add -DCMAKE_TOOLCHAIN_FILE... to the end of your cmake command
# you can get it from `vcpkg integrate install`
if(DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "" FORCE)
else()
    message(STATUS "Vcpkg wasn't found, please follow instructions from `vcpkg integrate install` or define VCPKG_ROOT "
                   "in your environment")
endif()


project(customspotify)

set(CMAKE_CXX_STANDARD 17)

# Qt5 from vcpkg
find_package(Qt5 COMPONENTS Core Widgets REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_subdirectory(hook)
add_executable(customspotify
        src/resources.qrc
        src/main.cpp
        src/windows/MainWindow.cpp src/windows/MainWindow.h
        src/loader/loader.cpp src/loader/loader.h src/loader/ntdll.h)

target_link_libraries(customspotify PRIVATE Qt::Core Qt5::Core Qt::WinMain Qt5::WinMain Qt::Widgets Qt5::Widgets Shlwapi.lib)

