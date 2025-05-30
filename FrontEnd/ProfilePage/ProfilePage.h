#ifndef PROFILEPAGE_H
#define PROFILEPAGE_H

#include <QDialog>
#include <QString>
#include "../../auth/UserAuthentication.h"
#include "../../auth/validation.h"
#include "../../auth/CommonPasswordChecker.h"

namespace Ui {
class ProfilePage;
}

class ProfilePage : public QDialog
{
    Q_OBJECT

public:
    explicit ProfilePage(const QString &username, QWidget *parent = nullptr);
    ~ProfilePage();

private slots:
    void on_changePasswordButton_clicked();

private:
    Ui::ProfilePage *ui;
    QString currentUsername;
    CommonPasswordChecker* passwordChecker;
    PasswordValidator* passwordValidator;
    UserAuthentication* userAuth;
    void updateMessageLabel(const QString& message, bool isError);
};

#endif // PROFILEPAGE_H 