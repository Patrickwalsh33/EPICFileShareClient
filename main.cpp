#include <QApplication>
#include "loginpage.h" // Include your LoginPage header
#include <QDebug>      // For any potential qDebug messages later (optional for now)

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    LoginPage loginDialog; // Create an instance of your LoginPage

    // Show the login dialog modally.
    // .exec() will block until the dialog is closed (e.g., by the user clicking 'X').
    // Since our button slots currently do nothing to close the dialog,
    // the user will have to manually close it.
    loginDialog.exec(); 

    // After the dialog is closed, the application will exit.
    // If you had logic in loginDialog to call accept() or reject(),
    // you could check the return value of exec() here.
    qDebug() << "Login dialog closed, application will exit."; // Optional debug message

    return 0; // Or return app.exec() if you had a main window to show after this.
              // For now, exiting after the login dialog is fine.
}
