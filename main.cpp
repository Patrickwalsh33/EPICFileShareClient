#include <QApplication>
#include "FrontEnd/LoginPage/loginpage.h"
#include "FrontEnd/HomePage/home.h"
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    HomePage homePage;
    homePage.show();

    return app.exec();
}
