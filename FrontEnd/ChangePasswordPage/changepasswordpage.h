#ifndef CHANGEPASSWORDPAGE_H
#define CHANGEPASSWORDPAGE_H

#include <QDialog>
#include "../../auth/UserAuthentication.h"
#include "../../auth/validation.h"
#include "../../auth/CommonPasswordChecker.h"

namespace Ui {
class ChangePasswordPage;
}

// Defines the ChangePasswordPage dialog window.
// TODO: Implement change password functionality
class ChangePasswordPage : public QDialog
{
    Q_OBJECT   //this is a Qt macro for enabling signals and slots etc

public:
    explicit ChangePasswordPage(QWidget *parent = nullptr); // explicit prevents implicit type conversion
    ~ChangePasswordPage(); //destructor

private slots:
    void on_changePasswordButton_clicked(); // TODO: Implement password change logic
    void on_cancelButton_clicked();

private:
    Ui::ChangePasswordPage *ui; // Pointer to the auto-generated UI class
    
    // Auth components
    CommonPasswordChecker* passwordChecker;
    PasswordValidator* passwordValidator;
    UserAuthentication* userAuth;

    // Helper methods
    void clearSensitiveData();
    void showSuccessMessage();
};

#endif // CHANGEPASSWORDPAGE_H 