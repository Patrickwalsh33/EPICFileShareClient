cmake_minimum_required(VERSION 3.16)
project(MyQtApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)


# Copy the password file to the build directory
configure_file(common_passwords.csv ${CMAKE_BINARY_DIR}/common_passwords.csv COPYONLY)



# Qt setup
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium)



add_executable(MyQtApp
        main.cpp
        FrontEnd/LoginPage/loginpage.cpp
        FrontEnd/LoginPage/loginpage.ui
        FrontEnd/HomePage/home.cpp
        FrontEnd/HomePage/home.ui
        X3DH/X3DH.h
        X3DH/X3DH.cpp
        FrontEnd/RegisterPage/registerpage.cpp
        FrontEnd/RegisterPage/registerpage.ui
        crypto/crypto_utils.cpp
        crypto/crypto_utils.h
        FrontEnd/UploadPage/uploadpage.cpp
        FrontEnd/UploadPage/uploadpage.h
        FrontEnd/UploadPage/uploadpage.ui
        auth/PasswordValidator.cpp
        auth/PasswordValidator.h
        auth/CommonPasswordChecker.cpp
        auth/CommonPasswordChecker.h
        auth/UserAuthentication.cpp
        auth/UserAuthentication.h
        FrontEnd/UploadPage/uploadManager.cpp
        FrontEnd/UploadPage/uploadManager.h
        key_management/EncryptionKeyGenerator.cpp
        key_management/EncryptionKeyGenerator.h
        key_management/MasterKeyDerivation.cpp
        key_management/MasterKeyDerivation.h
        key_management/FileKeyManager.cpp
        key_management/FileKeyManager.h
        key_management/UserKeyGenerator.cpp
        key_management/UserKeyGenerator.h
        key_management/KEKManager.cpp
        key_management/KEKManager.h
)

target_include_directories(MyQtApp PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/Password
        PkgConfig::LIBSODIUM
)

target_link_libraries(MyQtApp
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
        PkgConfig::LIBSODIUM
)



