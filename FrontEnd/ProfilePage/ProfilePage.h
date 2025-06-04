#ifndef PROFILEPAGE_H
#define PROFILEPAGE_H

#include <QDialog> //Base class for dialog
#include <QString> 
#include "../../auth/UserAuthentication.h"
#include "../../auth/validation.h"
#include "../../auth/CommonPasswordChecker.h"

namespace Ui { //prevent naming collisons and are good for organsing code
class ProfilePage; 
}

class ProfilePage : public QDialog
{
    Q_OBJECT // qt macro that enables signals and slots

public:
    //constructor
    explicit ProfilePage(const QString &username, QWidget *parent = nullptr); 

    //destructor
    ~ProfilePage();

private slots:
    void on_changePasswordButton_clicked();
    void on_backButton_clicked();

private:
    Ui::ProfilePage *ui;
    QString currentUsername;
    CommonPasswordChecker* passwordChecker;
    PasswordValidator* passwordValidator;
    UserAuthentication* userAuth;
    std::string user;
    std::string package;
    void updateMessageLabel(const QString& message, bool isError);
};

#endif // PROFILEPAGE_H 