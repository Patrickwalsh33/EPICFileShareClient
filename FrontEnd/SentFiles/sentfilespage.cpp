#include "sentfilespage.h"
#include "ui_sentfilespage.h"
#include "../HomePage/homepage.h"
#include "../SessionManager/SessionManager.h" // Required for server URL, adjust if already available
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QMouseEvent>

SentFilesPage::SentFilesPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SentFilesPage),
    m_sentFilesManager(new SentFilesManager(this)),
    selectedFileIndex(-1)
{
    ui->setupUi(this);


    if (!ui->scrollAreaWidgetContents->layout()) {
        QVBoxLayout *layout = new QVBoxLayout(ui->scrollAreaWidgetContents);
        ui->scrollAreaWidgetContents->setLayout(layout);
    }

    QVBoxLayout* scrollLayout = qobject_cast<QVBoxLayout*>(ui->scrollAreaWidgetContents->layout());
    if (scrollLayout) {
        scrollLayout->setAlignment(Qt::AlignTop); // New items appear at the top
        scrollLayout->setSpacing(10);
    }


    QString serverUrl = SessionManager::getInstance()->getServerUrl();
    if (serverUrl.isEmpty()) {
        qWarning() << "Server URL is not available from SessionManager. Please configure it.";

        QMessageBox::critical(this, "Configuration Error", "Server URL is not configured. Cannot fetch files.");
        ui->getSentFilesButton->setEnabled(false);
    } else {
        m_sentFilesManager->setServerUrl(serverUrl);
    }

    connect(m_sentFilesManager, &SentFilesManager::ownedFileUuidsReceived, this, &SentFilesPage::handleOwnedFileUuidsResponse);
    connect(m_sentFilesManager, &SentFilesManager::fetchOwnedFileUuidsFailed, this, &SentFilesPage::handleFetchUuidsError);
    connect(m_sentFilesManager, &SentFilesManager::fileDeleteSucceeded, this, &SentFilesPage::handleFileDeleteSuccess);
    connect(m_sentFilesManager, &SentFilesManager::fileDeleteFailed, this, &SentFilesPage::handleFileDeleteError);

    connect(ui->getSentFilesButton, &QPushButton::clicked, this, &SentFilesPage::on_getSentFilesButton_clicked);
    connect(ui->deleteButton, &QPushButton::clicked, this, &SentFilesPage::on_deleteButton_clicked);


    updateButtonStates();
}

SentFilesPage::~SentFilesPage()
{
    delete ui;
    // m_sentFilesManager is a child of SentFilesPage, so it will be deleted automatically by Qt's parent-child mechanism
}

void SentFilesPage::on_backButton_clicked()
{

    this->accept(); // Closes this dialog
    HomePage *homePage = new HomePage("", nullptr);
    homePage->setAttribute(Qt::WA_DeleteOnClose);
    homePage->exec(); // Shows HomePage modally
}

void SentFilesPage::on_getSentFilesButton_clicked()
{
    // Clear previous file boxes
    QLayout *layout = ui->scrollAreaWidgetContents->layout();
    QLayoutItem *item;
    while ((item = layout->takeAt(0)) != nullptr) {
        delete item->widget();
        delete item;
    }
    sentFilesList.clear();
    selectedFileIndex = -1;
    updateButtonStates();

    ui->getSentFilesButton->setEnabled(false);
    ui->getSentFilesButton->setText("Fetching...");

    m_sentFilesManager->fetchOwnedFileUuids();
}

void SentFilesPage::handleOwnedFileUuidsResponse(const QByteArray &serverResponse)
{
    ui->getSentFilesButton->setEnabled(true);
    ui->getSentFilesButton->setText("Get Sent Files");

    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(serverResponse, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        handleFetchUuidsError("Failed to parse server response: " + parseError.errorString());
        return;
    }

    if (!jsonDoc.isObject()) {
        handleFetchUuidsError("Invalid JSON response format: not an object.");
        return;
    }

    QJsonObject jsonObj = jsonDoc.object();
    if (!jsonObj.contains("status") || jsonObj["status"].toString() != "success") {
        QString message = jsonObj.contains("message") ? jsonObj["message"].toString() : "Unknown error from server.";
        handleFetchUuidsError("Failed to get owned UUIDs: " + message);
        return;
    }

    if (!jsonObj.contains("owned_file_uuids") || !jsonObj["owned_file_uuids"].isArray()) {
        handleFetchUuidsError("Invalid JSON response format: 'owned_file_uuids' missing or not an array.");
        return;
    }

    QJsonArray uuidsArray = jsonObj["owned_file_uuids"].toArray();
    if (uuidsArray.isEmpty()) {
        // Display a message in the scroll area if no files are found
        QLabel* noFilesLabel = new QLabel("You have not sent any files yet.");
        noFilesLabel->setAlignment(Qt::AlignCenter);
        noFilesLabel->setStyleSheet("font-size: 16px; color: grey; margin-top: 20px;");
        ui->scrollAreaWidgetContents->layout()->addWidget(noFilesLabel);
        return;
    }

    for (const QJsonValue &value : uuidsArray) {
        if (value.isString()) {
            SentFileInfo fileInfo;
            fileInfo.uuid = value.toString();
            fileInfo.index = sentFilesList.size();
            createFileBox(fileInfo); // This will also add it to sentFilesList internally now
        }
    }
}

void SentFilesPage::handleFetchUuidsError(const QString &error)
{
    ui->getSentFilesButton->setEnabled(true);
    ui->getSentFilesButton->setText("Get Sent Files");
    QMessageBox::warning(this, "Fetch Error", error);
}

void SentFilesPage::createFileBox(SentFileInfo& fileInfo) // CPR Pass by reference
{
    QFrame *box = new QFrame();
    box->setFrameShape(QFrame::StyledPanel);
    box->setLineWidth(1);
    box->setCursor(Qt::PointingHandCursor);
    box->setObjectName("fileBox_" + QString::number(fileInfo.index));
    box->setStyleSheet("QFrame { background-color: #f0f0f0; border: 1px solid #d0d0d0; border-radius: 5px; }" 
                       "QFrame:hover { background-color: #e0e0e0; }");
    box->setFixedHeight(60);

    QVBoxLayout *boxLayout = new QVBoxLayout(box);
    boxLayout->setContentsMargins(10, 5, 10, 5);

    fileInfo.nameLabel = new QLabel("File UUID: " + fileInfo.uuid, box);
    fileInfo.nameLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    


    boxLayout->addWidget(fileInfo.nameLabel);

    boxLayout->addStretch();

    box->setLayout(boxLayout);
    box->setProperty("fileIndex", fileInfo.index);
    box->installEventFilter(this);

    ui->scrollAreaWidgetContents->layout()->addWidget(box);
    fileInfo.displayBox = box;
    sentFilesList.append(fileInfo);
}


bool SentFilesPage::eventFilter(QObject *watched, QEvent *event)
{
    QFrame *frame = qobject_cast<QFrame*>(watched);
    if (frame && frame->objectName().startsWith("fileBox_")) {
        if (event->type() == QEvent::MouseButtonPress) {
            QMouseEvent *mouseEvent = static_cast<QMouseEvent*>(event);
            if (mouseEvent->button() == Qt::LeftButton) {
                int index = frame->property("fileIndex").toInt();
                onFileBoxClicked(index);
                return true; // Event handled
            }
        }
    }
    return QDialog::eventFilter(watched, event);
}

void SentFilesPage::onFileBoxClicked(int index)
{
    if (index < 0 || index >= sentFilesList.size()) return;

    // Deselect previous box
    if (selectedFileIndex != -1 && selectedFileIndex < sentFilesList.size()) {
        if (sentFilesList[selectedFileIndex].displayBox) {
            sentFilesList[selectedFileIndex].displayBox->setStyleSheet(
                "QFrame { background-color: #f0f0f0; border: 1px solid #d0d0d0; border-radius: 5px; }" 
                "QFrame:hover { background-color: #e0e0e0; }"
            );
        }
    }

    selectedFileIndex = index;

    // Select new box
    if (sentFilesList[selectedFileIndex].displayBox) {
        sentFilesList[selectedFileIndex].displayBox->setStyleSheet(
            "QFrame { background-color: #cce5ff; border: 2px solid #007bff; border-radius: 5px; }"
        );
    }
    updateButtonStates();
}

void SentFilesPage::updateButtonStates()
{
    bool fileSelected = (selectedFileIndex != -1);
    ui->deleteButton->setEnabled(fileSelected);
    ui->revokeButton->setEnabled(fileSelected);
}

void SentFilesPage::on_deleteButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= sentFilesList.size()) {
        QMessageBox::warning(this, "No File Selected", "Please select a file to delete.");
        return;
    }

    const QString& uuidToDelete = sentFilesList[selectedFileIndex].uuid;
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Confirm Delete", 
                                  QString("Are you sure you want to permanently delete file UUID: %1?").arg(uuidToDelete),
                                  QMessageBox::Yes|QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        qDebug() << "Attempting to delete file with UUID:" << uuidToDelete;
        ui->deleteButton->setEnabled(false);
        ui->deleteButton->setText("Deleting...");
        ui->revokeButton->setEnabled(false); // Disable revoke during delete operation as well
        m_sentFilesManager->deleteFile(uuidToDelete);
    }
}

void SentFilesPage::handleFileDeleteSuccess(const QString &deleted_uuid, const QByteArray &serverResponse)
{
    ui->deleteButton->setText("Delete File"); // Reset button text first

    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(serverResponse, &parseError);
    QString serverMessage = "File deleted."; // Default message

    if (parseError.error == QJsonParseError::NoError && jsonDoc.isObject()) {
        QJsonObject jsonObj = jsonDoc.object();
        if (jsonObj.contains("message") && jsonObj["message"].isString()) {
            serverMessage = jsonObj["message"].toString();
        }
        if (!jsonObj.contains("status") || jsonObj["status"].toString() != "success") {
            QString errorDetail = jsonObj.contains("message") ? jsonObj["message"].toString() : "Server indicated failure.";
            handleFileDeleteError(deleted_uuid, "Deletion failed: " + errorDetail);
            return; // Important to return here
        }
    } else if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "Could not parse delete success response:" << parseError.errorString();
        // Proceed with UI update but maybe with a generic message or warning for admin
    }

    QMessageBox::information(this, "Delete Successful", serverMessage);

    int removedIdx = -1;
    for (int i = 0; i < sentFilesList.size(); ++i) {
        if (sentFilesList[i].uuid == deleted_uuid) {
            removedIdx = i;
            break;
        }
    }

    if (removedIdx != -1) {
        SentFileInfo& info = sentFilesList[removedIdx];
        if (info.displayBox) {
            ui->scrollAreaWidgetContents->layout()->removeWidget(info.displayBox);
            info.displayBox->deleteLater(); // Use deleteLater for QObjects from event handlers
        }
        sentFilesList.removeAt(removedIdx);

        // Update indices for subsequent items
        for (int i = removedIdx; i < sentFilesList.size(); ++i) {
            sentFilesList[i].index = i;
            if (sentFilesList[i].displayBox) {
                sentFilesList[i].displayBox->setProperty("fileIndex", i);
            }
        }
        
        selectedFileIndex = -1; // Deselect
    }

    if (sentFilesList.isEmpty()) {
        // Clear layout first (in case any selection highlight was there)
        QLayout *layout = ui->scrollAreaWidgetContents->layout();
        QLayoutItem *item;
        while ((item = layout->takeAt(0)) != nullptr) { // Should be empty now, but good practice
            delete item->widget(); 
            delete item;           
        }
        QLabel* noFilesLabel = new QLabel("You have not sent any files yet.");
        noFilesLabel->setAlignment(Qt::AlignCenter);
        noFilesLabel->setStyleSheet("font-size: 16px; color: grey; margin-top: 20px;");
        ui->scrollAreaWidgetContents->layout()->addWidget(noFilesLabel);
    }

    updateButtonStates();
}

void SentFilesPage::handleFileDeleteError(const QString &failed_uuid, const QString &error)
{
    QMessageBox::warning(this, "Delete Failed", "Could not delete file UUID: " + failed_uuid + "\nError: " + error);
    ui->deleteButton->setText("Delete File");
    // Re-enable buttons based on current selection state (updateButtonStates handles this)
    updateButtonStates();
}

void SentFilesPage::on_revokeButton_clicked()
{
    if (selectedFileIndex == -1) return;
    // Placeholder for revoke functionality
    qDebug() << "Revoke button clicked for UUID:" << sentFilesList[selectedFileIndex].uuid;
    QMessageBox::information(this, "Revoke Access", "Revoke access functionality for UUID " + sentFilesList[selectedFileIndex].uuid + " will be implemented here.");
} 