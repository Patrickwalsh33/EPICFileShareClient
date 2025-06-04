#include "landingpage.h"
#include "ui_landingpage.h" 
#include "../LoginPage/loginpage.h"
#include "../RegisterPage/registerpage.h"
#include "../HomePage/homepage.h" // Include HomePage header

#include <QDebug> //include debug

//Constructor This  initializes LandingPage and sets up the ui from landingpage.ui
LandingPage::LandingPage(QWidget *parent) :
    QDialog(parent), //initalizes parent class
    ui(new Ui::LandingPage)  //creates ui object
{
    ui->setupUi(this); //setup the widgets and layouts designed in landingpage.ui
}

//Destructor
LandingPage::~LandingPage(){

    delete ui; 
}

//Slot for handling the login buttons clicked 
void LandingPage::on_navigateToLoginButton_clicked() {
    LoginPage loginDialog(nullptr); //create login page dialog
    loginDialog.setAttribute(Qt::WA_DeleteOnClose); //auto delete when closed
    this->accept(); // Close LandingPage and signal acceptance
    loginDialog.exec(); // Show LoginPage 
    // Flow returns to main.cpp after LoginPage is closed
}
//slot for handling the registerbutton being clicked
void LandingPage::on_navigateToRegisterButton_clicked() {  
    RegisterPage registerDialog(nullptr);
    registerDialog.setAttribute(Qt::WA_DeleteOnClose); 
    this->accept(); // Close
    registerDialog.exec(); // Show RegisterPage 
}