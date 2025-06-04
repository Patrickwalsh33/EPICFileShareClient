#include "recievedfilespage.h"
#include "ui_recievedfilespage.h"
#include "../HomePage/homepage.h"
#include <QDebug>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QEvent>
#include <QMouseEvent>  //qt mouse events

//constructor
RecievedFilesPage::RecievedFilesPage(QWidget *parent) :
    QDialog(parent),  //initialize parent class 
    ui(new Ui::RecievedFilesPage)    //create ui object
{
    ui->setupUi(this);    //set up ui elements

    //connect buttons to slots
    connect(ui->getFilesButton, &QPushButton::clicked, this, &RecievedFilesPage::on_getFilesButton_clicked);
    connect(ui->decryptButton, &QPushButton::clicked, this, &RecievedFilesPage::on_decryptButton_clicked);
    connect(ui->downloadButton, &QPushButton::clicked, this, &RecievedFilesPage::on_downloadButton_clicked);
    connect(ui->backButton, &QPushButton::clicked, this, &RecievedFilesPage::on_backButton_clicked);


//creates layout for scroll area
    if (!ui->scrollAreaWidgetContents->layout()) {
        QVBoxLayout* scrollLayout = new QVBoxLayout(ui->scrollAreaWidgetContents);
        scrollLayout->setSpacing(10);
        scrollLayout->setContentsMargins(0,0,0,0);
        ui->scrollAreaWidgetContents->setLayout(scrollLayout);
    }

    updateButtonStates(); //initalize button states
}
//destructor
RecievedFilesPage::~RecievedFilesPage()
{
    delete ui;
}

//creates ui elements for a file entry
bool RecievedFilesPage::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        QMouseEvent *mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton) {
            for (int i = 0; i < receivedFiles.size(); ++i) {
                if (watched == receivedFiles[i].displayBox) {
                    onFileBoxClicked(i);
                    return true; // Event handled
                }
            }
        }
    }
    return QDialog::eventFilter(watched, event); // Pass on unhandled events
}

//handles get files button click
void RecievedFilesPage::on_getFilesButton_clicked()
{
    qDebug() << "Get Files button clicked. Implement fetching logic here.";
    while (QLayoutItem* item = ui->scrollAreaWidgetContents->layout()->takeAt(0)) {
        if (item->widget()) {
            item->widget()->removeEventFilter(this); // Important: remove event filter before deleting
            delete item->widget();
        }
        delete item;
    }
    receivedFiles.clear();
    selectedFileIndex = -1;

    ReceivedFileInfo file1;
    file1.fileName = "Document1.enc";
    file1.sender = "UserA";
    file1.fileSize = 1024 * 5;
    file1.isDecrypted = false;
    file1.uuid = "uuid1";
    file1.index = receivedFiles.size();
    receivedFiles.append(file1);
    createFileBox(receivedFiles.last());

    ReceivedFileInfo file2;
    file2.fileName = "Picture.jpg.enc";
    file2.sender = "UserB";
    file2.fileSize = 1024 * 1024 * 2;
    file2.isDecrypted = false;
    file2.uuid = "uuid2";
    file2.index = receivedFiles.size();
    receivedFiles.append(file2);
    createFileBox(receivedFiles.last());

    ReceivedFileInfo file3;
    file3.fileName = "Archive.zip.enc";
    file3.sender = "UserC";
    file3.fileSize = 1024 * 1024 * 15;
    file3.isDecrypted = true;
    file3.uuid = "uuid3";
    file3.index = receivedFiles.size();
    receivedFiles.append(file3);
    createFileBox(receivedFiles.last());
    
    updateButtonStates();
}

//creates ui for file entry
void RecievedFilesPage::createFileBox(ReceivedFileInfo& fileInfo) {
    QFrame* box = new QFrame(ui->scrollAreaWidgetContents);
    box->setObjectName("fileBox_" + fileInfo.uuid);
    box->setMinimumHeight(90);
    box->setStyleSheet("QFrame { background-color: #f0f0f0; border: 1px solid #ccc; border-radius: 4px; }");
    box->setCursor(Qt::PointingHandCursor);
    box->installEventFilter(this);

    QVBoxLayout* boxLayout = new QVBoxLayout(box);
    boxLayout->setContentsMargins(10, 5, 10, 5);
    boxLayout->setSpacing(3);

    fileInfo.nameLabel = new QLabel("File: " + fileInfo.fileName, box);
    fileInfo.nameLabel->setStyleSheet("font-weight: bold; font-size: 14px;");

    fileInfo.senderLabel = new QLabel("From: " + fileInfo.sender, box);
    fileInfo.senderLabel->setStyleSheet("font-size: 12px; color: #333;");
    
    QLabel* sizeLabel = new QLabel("Size: " + formatFileSize(fileInfo.fileSize), box);
    sizeLabel->setStyleSheet("font-size: 12px; color: #555;");

    fileInfo.statusLabel = new QLabel(fileInfo.isDecrypted ? "Status: Decrypted" : "Status: Encrypted", box);
    fileInfo.statusLabel->setStyleSheet(fileInfo.isDecrypted ? "color: #28a745;" : "color: #dc3545;");

    boxLayout->addWidget(fileInfo.nameLabel);
    boxLayout->addWidget(fileInfo.senderLabel);
    boxLayout->addWidget(sizeLabel);
    boxLayout->addWidget(fileInfo.statusLabel);

    fileInfo.displayBox = box;

    QVBoxLayout* scrollLayout = qobject_cast<QVBoxLayout*>(ui->scrollAreaWidgetContents->layout());
    if (scrollLayout) {
        scrollLayout->insertWidget(0, box);
    } else {
        qDebug() << "Error: scrollAreaWidgetContents does not have a QVBoxLayout.";
    }
}

//handles file box selection
void RecievedFilesPage::onFileBoxClicked(int index) {
    if (index < 0 || index >= receivedFiles.size()) {
        qDebug() << "Invalid file index clicked:" << index;
        return;
    }

    qDebug() << "File box clicked, index:" << index << ", Name:" << receivedFiles[index].fileName;

    if (selectedFileIndex != -1 && selectedFileIndex < receivedFiles.size()) {
        if (receivedFiles[selectedFileIndex].displayBox) {
            bool isDec = receivedFiles[selectedFileIndex].isDecrypted;
            QString baseStyle = "QFrame { background-color: #f0f0f0; border: 1px solid #ccc; border-radius: 4px; }";
            if (isDec) {
                 baseStyle = "QFrame { background-color: #e8f5e9; border: 1px solid #4CAF50; border-radius: 4px; }";
            }
            receivedFiles[selectedFileIndex].displayBox->setStyleSheet(baseStyle);
        }
    }
    
    selectedFileIndex = index;

    if (receivedFiles[selectedFileIndex].displayBox) {
        bool isDec = receivedFiles[selectedFileIndex].isDecrypted;
        QString selectedStyle = "QFrame { background-color: #e0e0e0; border: 2px solid #007bff; border-radius: 4px; }";
         if (isDec) {
            selectedStyle = "QFrame { background-color: #d4edda; border: 2px solid #007bff; border-radius: 4px; }";
        }
        receivedFiles[selectedFileIndex].displayBox->setStyleSheet(selectedStyle);
    }

    updateButtonStates();
}


//updates enabled state and style of action buttons
void RecievedFilesPage::updateButtonStates() {
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size()) {
        ui->decryptButton->setEnabled(false);
        ui->downloadButton->setEnabled(false);
        ui->decryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        return;
    }

    const auto& selectedFile = receivedFiles[selectedFileIndex];

    if (!selectedFile.isDecrypted) {
        ui->decryptButton->setEnabled(true);
        ui->downloadButton->setEnabled(false);
        ui->decryptButton->setStyleSheet("color: white; background-color: #2196F3; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
    } else {
        ui->decryptButton->setEnabled(false);
        ui->downloadButton->setEnabled(true);
        ui->decryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setStyleSheet("color: white; background-color: #4CAF50; border: none; border-radius: 15px; font-size: 22px;");
    }
}

//handles decrypt button click
void RecievedFilesPage::on_decryptButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size() || receivedFiles[selectedFileIndex].isDecrypted) {
        qDebug() << "Decrypt button clicked, but no valid file selected or file already decrypted.";
        return;
    }

    qDebug() << "Decrypting file:" << receivedFiles[selectedFileIndex].fileName;
    QMessageBox::information(this, "Decryption Started", "Decrypting " + receivedFiles[selectedFileIndex].fileName + "...");
    
    receivedFiles[selectedFileIndex].isDecrypted = true;
    if (receivedFiles[selectedFileIndex].displayBox) {
        receivedFiles[selectedFileIndex].statusLabel->setText("Status: Decrypted");
        receivedFiles[selectedFileIndex].statusLabel->setStyleSheet("color: #28a745;");
        receivedFiles[selectedFileIndex].displayBox->setStyleSheet("QFrame { background-color: #d4edda; border: 2px solid #007bff; border-radius: 4px; }");
    }
    
    updateButtonStates();
    QMessageBox::information(this, "Decryption Complete", receivedFiles[selectedFileIndex].fileName + " has been decrypted.");
}


//handles download button click
void RecievedFilesPage::on_downloadButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size() || !receivedFiles[selectedFileIndex].isDecrypted) {
         qDebug() << "Download button clicked, but no valid decrypted file selected.";
        return;
    }

    const auto& fileToDownload = receivedFiles[selectedFileIndex];
    qDebug() << "Downloading file:" << fileToDownload.fileName;
    
    QMessageBox::information(this, "Download Started", "Downloading " + fileToDownload.fileName + "...");

    updateButtonStates();
    QMessageBox::information(this, "Download Complete", fileToDownload.fileName + " has been 'downloaded' (simulated).");
}

//handles back button click
void RecievedFilesPage::on_backButton_clicked()
{
    reject();
    qDebug() << "Back button clicked, closing RecievedFilesPage.";
}

// formats file size into human readable string
QString RecievedFilesPage::formatFileSize(qint64 size) {
    if (size < 1024)
        return QString("%1 bytes").arg(size);
    else if (size < 1024 * 1024)
        return QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
    else if (size < 1024 * 1024 * 1024)
        return QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
    else
        return QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
}

// Updates file display info
void RecievedFilesPage::updateFileInfoDisplay(int index) {
    Q_UNUSED(index);
} 