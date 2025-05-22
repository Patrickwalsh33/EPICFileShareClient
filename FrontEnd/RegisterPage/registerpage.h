#ifndef REGISTERPAGE_H
#define REGISTERPAGE_H


#include <QDialog>
#include <QStringList>
#include <QFile>
#include <QTextStream>


namespace Ui {
class RegisterPage;
}

// Defines the RegisterPage dialog window.
class RegisterPage : public QDialog
{
    Q_OBJECT   //this is a Qt macro for enabling signals and slots etc

public:
    explicit RegisterPage(QWidget *parent = nullptr); // explicit prevents implicit type conversion i
    ~RegisterPage(); //destructor

private slots:
    void on_registerButton_clicked();
    void on_backToLoginButton_clicked();

private:
    Ui::RegisterPage *ui; // Pointer to the auto-generated UI class

    //Nist SP800-63B password validation

    bool validatePassword(const QString& password, const QString& confirmPassword, QString& errorMsg);
    bool validateUsername(const QString& username, QString& errorMsg); //function can change error message but cant change username


    //methods for loading common passwords there in a csv file for now
    QStringList loadCommonPasswordsFromCSV();
    QStringList commonPasswords; 

    int failed;

};

#endif 