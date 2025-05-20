cmake_minimum_required(VERSION 3.16)
project(MyQtApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Do NOT hardcode paths – rely on Qt6_DIR set via environment or CLion config
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)

add_executable(MyQtApp
        main.cpp
        Password/PasswordHashing.cpp
        Password/PasswordHashing.h

)
target_include_directories(MyQtApp PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/Password
        PkgConfig::LIBSODIUM
)


target_link_libraries(MyQtApp
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets

        PkgConfig::LIBSODIUM
)
