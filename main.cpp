#include <QApplication>
#include <QPushButton>
#include <iostream>
#include <string>

#include "Password/PasswordHashing.h"

int main(int argc, char *argv[]) {

    PasswordHashing hashtest;
    std::string Password;
    std::cout<<"Enter a Password"<<std::endl;
    std::cin>>Password;
    std::string hashedpass = hashtest.hashPassword(Password);
    std::cout<<"Hashed Password: "<<hashedpass<<std::endl;
    QApplication a(argc, argv);
    QPushButton button("Hello world!", nullptr);
    button.resize(200, 100);
    button.show();
    return QApplication::exec();

}
