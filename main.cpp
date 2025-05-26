#include <QApplication>
#include "FrontEnd/LoginPage/loginpage.h"
#include "FrontEnd/HomePage/home.h"
#include <QDebug>
#include "X3DH/X3DH.h"
#include "Testing/X3DHTest.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

//    HomePage homePage;
//    homePage.show();

      test_file_encryption_flow();

    return app.exec();
}
