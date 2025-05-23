#ifndef COMMONPASSWORDCHECKER_H
#define COMMONPASSWORDCHECKER_H

#include <QStringList>
#include <QFile>
#include <QTextStream>
#include <QDebug>

class CommonPasswordChecker {
public:
    CommonPasswordChecker();

    //methods for loading common passwords there in a csv file for now
    QStringList loadCommonPasswordsFromCSV();
    bool isCommonPassword(const QString& password);
    int getPasswordCount() const;

private:
    QStringList commonPasswords; 
};

#endif //COMMONPASSWORDCHECKER_H
