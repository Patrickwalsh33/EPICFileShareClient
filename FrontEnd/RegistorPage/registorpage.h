#ifndef REGISTORPAGE_H
#define REGISTORPAGE_H

#include <QDialog>

namespace Ui {
class RegistorPage;
}

// Defines the RegistorPage dialog window.
class RegistorPage : public QDialog
{
    Q_OBJECT 

public:
    explicit RegistorPage(QWidget *parent = nullptr);
    ~RegistorPage();

private slots:
    void on_registerButton_clicked();
    void on_backToLoginButton_clicked();

private:
    Ui::RegistorPage *ui; // Pointer to the auto-generated UI class
};

#endif 