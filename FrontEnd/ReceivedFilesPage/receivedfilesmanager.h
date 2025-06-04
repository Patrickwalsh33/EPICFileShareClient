#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslError>

class ReceivedFilesManager : public QObject
{
    Q_OBJECT

public:
    explicit ReceivedFilesManager(QObject *parent = nullptr);
    ~ReceivedFilesManager();

    void fetchUnreadMessages();
    void setServerUrl(const QString &url);

signals:
    void unreadMessagesReceived(const QByteArray &serverResponse);
    void fetchMessagesFailed(const QString &error);
    void sslErrorsSignal(const QString &error); // Renamed to avoid conflict if class is used elsewhere

private slots:
    void handleInboxResponse();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError errorCode);

private:
    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;
    QString serverUrl;
}; 