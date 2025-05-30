#pragma once

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslError>

class RegisterManager : public QObject
{
Q_OBJECT

public:
    explicit RegisterManager(QObject *parent = nullptr);
    ~RegisterManager();

    void setServerUrl(const QString &url);
    bool sendRegistrationData(const QJsonObject& registrationData);

signals:
    void registrationSucceeded();
    void registrationFailed(const QString &error);

private slots:
    void handleRegistrationFinished();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;
    QString serverUrl;
};