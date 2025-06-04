#ifndef LANDINGPAGE_H
#define LANDINGPAGE_H 

#include <QDialog> //qt dialog window class

//good for preventing naming colisions
namespace Ui { 
    class LandingPage;
}

class HomePage; // Forward declaration

//our class inherits from qdialog
class LandingPage : public QDialog{
    Q_OBJECT //qt macro for signals and slots

public:
    //constructor
    explicit LandingPage(QWidget *parent = nullptr); 
    //destructor
    ~LandingPage();

private slots:
    void on_navigateToLoginButton_clicked(); 
    void on_navigateToRegisterButton_clicked(); 

private:
    Ui::LandingPage *ui; //pointer to ui class

};
#endif
