#ifndef REGISTERPAGE_H
#define REGISTERPAGE_H

#include <QDialog>

namespace Ui {
class RegisterPage;
}

// Defines the RegisterPage dialog window.
class RegisterPage : public QDialog
{
    Q_OBJECT 

public:
    explicit RegisterPage(QWidget *parent = nullptr);
    ~RegisterPage();

private slots:
    void on_registerButton_clicked();
    void on_backToLoginButton_clicked();

private:
    Ui::RegisterPage *ui; // Pointer to the auto-generated UI class
};

#endif 