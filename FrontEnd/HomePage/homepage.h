#ifndef HOMEPAGE_H
#define HOMEPAGE_H

#include <QDialog> //Base class for dialog windows in QT
#include <QString> //Qt string class, 

//forward declarations. Basically tells complier the classes exist without including full headers
namespace Ui { // prevent naming collisons and are good for organsing code
class HomePage;
}
class ProfilePage; 
class UploadPage;

//main hompage class that inherits from QDialog
class HomePage : public QDialog {
    Q_OBJECT    //special qt macro it basically enables signals and slots

public:
    //Constructor
    explicit HomePage(const QString &username, QWidget *parent = nullptr); //null pointer good for memory management

    //destructor
    ~HomePage(); 


//these handle events
private slots: 
    void on_profileButton_clicked();
    void on_uploadButton_clicked();
    void on_filesSentButton_clicked();
    void on_filesReceivedButton_clicked();

private:
    Ui::HomePage *ui;    //pointer to the ui page
    QString currentUsername;      //stores the logged in username
};

#endif 