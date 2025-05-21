#include <QApplication>
#include "FrontEnd/LoginPage/loginpage.h"
#include "FrontEnd/HomePage/home.h"
#include <QDebug>
#include "X3DH/X3DH.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    HomePage homePage;
    homePage.show();

    run_x3dh_demo();

    return app.exec();
}
