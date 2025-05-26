//
// Created by Andrew Jaffray on 23/05/2025.
//

#ifndef UPLOADPAGE_H
#define UPLOADPAGE_H

#include <QDialog>
#include <QString>

namespace Ui {
    class UploadPage;
}

// Defines the UploadPage dialog window for file uploads.
class UploadPage : public QDialog
{
Q_OBJECT // Enables Qt's meta-object system (signals, slots, etc.).

public:
    explicit UploadPage(QWidget *parent = nullptr); // Constructor: Initializes the UploadPage.
    ~UploadPage(); // Destructor: Cleans up resources.

private slots:
    void on_selectFileButton_clicked(); // Slot for handling file selection button clicks.
    void on_uploadButton_clicked(); // Slot for handling upload button clicks.
    void on_backButton_clicked(); // Slot for handling back button clicks.

private:
    Ui::UploadPage *ui; // Pointer to the auto-generated UI class from uploadpage.ui.
    QString selectedFilePath; // Stores the path of the selected file.
    void updateFileInfo(); // Updates the file information display.
};

#endif // UPLOADPAGE_H