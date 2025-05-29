#pragma once

#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslError>

class LoginManager : public QObject
{
Q_OBJECT

public:
    explicit LoginManager(QObject *parent = nullptr);
    ~LoginManager();

    void setServerUrl(const QString &url);
    bool requestChallenge(const QString &username);
    bool submitLogin(const QString &username, const QByteArray &signature, const QByteArray &nonce);

signals:
    void challengeReceived(const QByteArray &nonce);
    void challengeFailed(const QString &error);
    void loginSucceeded();
    void loginFailed(const QString &error);

private slots:
    void handleChallengeResponse();
    void handleLoginResponse();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;
    QString serverUrl;

    enum RequestType {
        Challenge,
        Login
    };
    RequestType currentRequestType;
}; 