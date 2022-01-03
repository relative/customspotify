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

# Qt5, nlohmann-json, efsw from vcpkg
find_package(Qt5 COMPONENTS Core Widgets REQUIRED)
find_package(efsw CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
set(CUSTOMSPOTIFY_LL Qt::Core Qt5::Core Qt::WinMain Qt5::WinMain Qt::Widgets Qt5::Widgets
        nlohmann_json nlohmann_json::nlohmann_json
        efsw::efsw)
add_subdirectory(hook)
add_executable(customspotify
        src/resources.qrc
        src/main.cpp
        src/startup.cpp src/startup.h
        src/loader/loader.cpp src/loader/loader.h src/loader/ntdll.h
        src/loader/eventsink.cpp src/loader/eventsink.h
        src/windows/MainWindow.cpp src/windows/MainWindow.h src/windows/MainWindow.ui
        src/windows/ScriptWidget.cpp src/windows/ScriptWidget.h src/windows/ScriptWidget.ui
        src/theme/theme.cpp src/theme/theme.h
        src/script/scriptmanager.cpp src/script/scriptmanager.h src/script/script.cpp src/script/script.h)

if (MSVC)
    target_link_libraries(customspotify PRIVATE
            ${CUSTOMSPOTIFY_LL}
            Shlwapi.lib wbemuuid.lib)
else()
    target_link_libraries(customspotify PRIVATE
            ${CUSTOMSPOTIFY_LL})
endif()

add_custom_target(hook_gui)
add_dependencies(hook_gui
        hook
        customspotify)