#pragma once

#include "authenticationTests.h"
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QEventLoop>
#include <QUrlQuery>

class networkTests : public TestSuite {
public:
    networkTests(QNetworkAccessManager* manager);

    QJsonObject performPostRequest(const QUrl& url, const QJsonObject& payload, int& httpStatusCode);
    QJsonObject performGetRequest(const QUrl& url, QUrlQuery& queryParams, int& httpStatusCode);

    bool testSuccessfulRegistration();
    bool testRegisterExistingUser();
    bool testChallengeRequestValidUser();
    bool testChallengeRequestInvalidUser();
    bool testLoginMissingFields();
    bool testLoginInvalidNonce();

    static void runAllNetworkTests(QNetworkAccessManager* manager);

private:
    QNetworkAccessManager* networkManager;
    QString registeredUsername;
    QString validNonceForLogin;
    const QString serverBaseUrl = "https://leftovers.gobbler.info";

    void demonstrateBasicPointers(int inputValue, int* outputValue);
    void demonstratePointerArithmeticAndArrays();
    void demonstrateFunctionPointers();

};