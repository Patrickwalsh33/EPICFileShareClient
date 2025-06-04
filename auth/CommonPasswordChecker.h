#ifndef COMMONPASSWORDCHECKER_H
#define COMMONPASSWORDCHECKER_H

#include <QStringList>
#include <QFile>
#include <QTextStream>
#include <QDebug>

class CommonPasswordChecker {
public:
    CommonPasswordChecker(); //constructor loads password

    //methods for loading common passwords there in a csv file for now
    QStringList loadCommonPasswordsFromCSV();

    //checks if a password is in comon passord list
    bool isCommonPassword(const QString& password);

    //gets count of loaded passwords
    int getPasswordCount() const;

private:
    QStringList commonPasswords;  //list of common passwords
};

#endif 
