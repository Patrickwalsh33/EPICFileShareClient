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
        auth/Validation.cpp
        auth/Validation.h
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
        key_management/KEKManager.cpp
        key_management/KEKManager.h
        key_management/X3DHKeys/IdentityKeyPair.cpp
        key_management/X3DHKeys/IdentityKeyPair.h
        key_management/X3DHKeys/EphemeralKeyPair.h
        key_management/X3DHKeys/EphemeralKeyPair.cpp
        key_management/X3DHKeys/OneTimeKeyPair.h
        key_management/X3DHKeys/OneTimeKeyPair.cpp
        key_management/X3DHKeys/SignedPreKeyPair.h
        key_management/X3DHKeys/SignedPreKeyPair.cpp
        Testing/X3DHTest.cpp
        Testing/X3DHTest.h
        key_management/DataEncryptionKey.h
        key_management/DataEncryptionKey.cpp
        key_management/KeyEncryptor.h
        key_management/KeyEncryptor.cpp
        crypto/uploadEncryption.h
        crypto/uploadEncryption.cpp
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



