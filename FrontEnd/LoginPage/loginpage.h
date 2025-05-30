#ifndef LOGINPAGE_H
#define LOGINPAGE_H

#include <QDialog>
#include "../ProfilePage/ProfilePage.h"

namespace Ui {
class LoginPage;
}

// Defines the LoginPage dialog window.
class LoginPage : public QDialog
{
    Q_OBJECT // Enables Qt's meta-object system (signals, slots, etc.).

public:
    explicit LoginPage(QWidget *parent = nullptr); // Constructor: Initializes the LoginPage.
    ~LoginPage(); // Destructor: Cleans up resources.

private slots:
    void on_loginButton_clicked(); // Slot for handling loginButton clicks.
    void on_goToRegistationButton_clicked(); // Slot for handling goToRegistationButton clicks.
    void on_goToProfileButton_clicked(); // Slot for handling goToProfileButton clicks.

private:
    Ui::LoginPage *ui; // Pointer to the auto-generated UI class from loginpage.ui.
};

#endif 