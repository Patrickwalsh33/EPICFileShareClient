#include <QApplication>
#include "FrontEnd/LoginPage/loginpage.h"
#include "FrontEnd/LandingPage/landingpage.h"
#include <QDebug>
#include "X3DH/X3DH.h"
#include "Testing/X3DHTest.h"
#include "key_management/DataEncryptionKey.h"
#include "crypto/crypto_utils.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    LandingPage landingPage;
    landingPage.show();

//    test_file_encryption_flow();
//    DataEncryptionKey dataKey;
//    print_hex("Randomly Generated Data Key: ", dataKey.getKey().data(), dataKey.getKey().size());

    return app.exec();
}
