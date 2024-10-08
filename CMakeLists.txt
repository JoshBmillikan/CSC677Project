cmake_minimum_required(VERSION 3.29)
project(CSC677Project)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)


find_package(Qt6 COMPONENTS
        Core
        Gui
        Widgets
        REQUIRED)

add_executable(CSC677Project src/application/main.cpp
        src/platform/platform.h
        src/platform/linux.cpp)
target_include_directories(CSC677Project PRIVATE src)

target_link_libraries(CSC677Project
        Qt::Core
        Qt::Gui
        Qt::Widgets
)

