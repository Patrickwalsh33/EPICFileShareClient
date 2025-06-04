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
add_subdirectory(keychain)


add_executable(MyQtApp
        main.cpp
        FrontEnd/LoginPage/loginpage.cpp
        FrontEnd/LoginPage/loginpage.ui
        FrontEnd/LandingPage/landingpage.cpp
        FrontEnd/LandingPage/landingpage.ui
        FrontEnd/ProfilePage/ProfilePage.cpp
        FrontEnd/ProfilePage/ProfilePage.ui
        FrontEnd/HomePage/homepage.cpp
        FrontEnd/HomePage/homepage.ui
        FrontEnd/SessionManager/SessionManager.cpp
        FrontEnd/SessionManager/SessionManager.h
        X3DH/X3DH_shared.h
        X3DH/X3DH_sender.cpp
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
        FrontEnd/RegisterPage/registerManager.cpp
        FrontEnd/RegisterPage/registerManager.h
        FrontEnd/SentFiles/sentfilespage.cpp
        FrontEnd/SentFiles/sentfilespage.h
        FrontEnd/SentFiles/sentfilespage.ui
        FrontEnd/SentFiles/sentfilesmanager.cpp
        FrontEnd/SentFiles/sentfilesmanager.h
        FrontEnd/RecievedFiles/recievedfilespage.cpp
        FrontEnd/RecievedFiles/recievedfilespage.h
        FrontEnd/RecievedFiles/recievedfilespage.ui
        X3DH/X3DH_reciever.cpp
        Testing/authenticationTests.cpp
        Testing/authenticationTests.h
        Testing/networkTests.cpp
        Testing/networkTests.h
        auth/RateLimiter.cpp
        auth/RateLimiter.h
        Backend/Decryption/DecryptionManager.cpp
        Backend/Decryption/DecryptionManager.h
        FrontEnd/ReceivedFilesPage/receivedfilesmanager.cpp
        FrontEnd/ReceivedFilesPage/receivedfilesmanager.h

)

target_include_directories(MyQtApp PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/Password
        ${CMAKE_CURRENT_SOURCE_DIR}/keychain/include
)

target_link_libraries(MyQtApp
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
        PkgConfig::LIBSODIUM
        keychain
)



