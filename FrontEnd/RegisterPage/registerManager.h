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
    static constexpr int DEFAULT_ONETIME_KEYS = 10;
    ~RegisterManager();

    void setServerUrl(const QString &url);
    bool registerUser(const QString &username, int numOneTimeKeys = DEFAULT_ONETIME_KEYS);

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