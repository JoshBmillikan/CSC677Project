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
        Designer
        REQUIRED)

add_subdirectory(external/libpcap EXCLUDE_FROM_ALL)

add_executable(CSC677Project src/application/main.cpp
        src/application/packet.cpp
        src/application/packet.h
        src/application/window.cpp
        src/application/window.h
        src/application/window.ui)
target_include_directories(CSC677Project PRIVATE src)

target_link_libraries(CSC677Project
        Qt::Core
        Qt::Gui
        Qt::Widgets
        Qt::Designer
        pcap
)

