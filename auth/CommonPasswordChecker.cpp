#include "CommonPasswordChecker.h"
#include <QFile>
#include <QTextStream>
#include <QDebug>

CommonPasswordChecker::CommonPasswordChecker() {
    commonPasswords = loadCommonPasswordsFromCSV();
    qDebug() << "Loaded" << commonPasswords.size() << "common passwords"; //should be about 10000
}

//loads common passwords from a CSV file
QStringList CommonPasswordChecker::loadCommonPasswordsFromCSV(){ 
    QStringList paswords;       //list to store passwords
    QFile file("common_passwords.csv");         //opens csv file
    
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);     //create stream to read the file

        //skip the header line
        if (!in.atEnd()){
            in.readLine();
        }
        
        // Read passwords from the first column
        while (!in.atEnd()) {
            QString line = in.readLine();
            QStringList fields = line.split(',');
            if (!fields.isEmpty()) {
                paswords << fields[0].trimmed();
            }
        }

        file.close();    
    } else {
        qDebug() << "failed to open the common passwords file";
    }

    return paswords;
}

bool CommonPasswordChecker::isCommonPassword(const QString& password) {
    return commonPasswords.contains(password.toLower());
}

int CommonPasswordChecker::getPasswordCount() const {
    return commonPasswords.size();
}
