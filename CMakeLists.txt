cmake_minimum_required(VERSION 3.16)
project(MyQtApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt setup
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

# Add this line to find libsodium (via vcpkg)
find_package(unofficial-sodium CONFIG REQUIRED)


add_executable(MyQtApp
        main.cpp
        FrontEnd/LoginPage/loginpage.cpp
        FrontEnd/LoginPage/loginpage.ui
        FrontEnd/HomePage/home.cpp
        FrontEnd/HomePage/home.ui
)

target_link_libraries(MyQtApp
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        unofficial-sodium::sodium
)

