#include "networkTests.h"
#include <iostream> // For std::cout
#include <QUuid>    // For generating unique enough usernames for testing
#include <QSslError>
#include <QSslConfiguration>
#include <QList>

networkTests::networkTests(QNetworkAccessManager* manager) : TestSuite ("Network Request Tests"), networkManager(manager) {
    registeredUsername = "testuser_" + QUuid::createUuid().toString(QUuid::Id128).left(8);

    addTest("Successful Registration", [this]() { return testSuccessfulRegistration(); });
    addTest("Register Existing User", [this]() { return testRegisterExistingUser(); });
    addTest("Challenge Request (Valid User)", [this]() { return testChallengeRequestValidUser(); });
    addTest("Challenge Request (Invalid User)", [this]() { return testChallengeRequestInvalidUser(); });
    addTest("Login Missing Fields", [this]() { return testLoginMissingFields(); });
    addTest("Login With Invalid Nonce", [this]() { return testLoginInvalidNonce(); });
}

QJsonObject networkTests::performPostRequest(const QUrl& url, const QJsonObject& payload, int& httpStatusCode) {
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = networkManager->post(request, QJsonDocument(payload).toJson());

    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec(); // Wait for the reply

    httpStatusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QByteArray responseData = reply->readAll();

    if (reply->error() != QNetworkReply::NoError) {
        std::cout << " [DEBUG] Network Error for POST " << url.toString().toStdString()
                  << ": " << reply->errorString().toStdString() << std::endl;

    }

    reply->deleteLater();

    if (responseData.isEmpty()) {
        std::cout << " [DEBUG] Empty response from server for POST " << url.toString().toStdString() << std::endl;
        return QJsonObject();
    }
    QJsonDocument jsonDoc = QJsonDocument::fromJson(responseData);
    if (jsonDoc.isNull() || !jsonDoc.isObject()) {
        std::cout << " [DEBUG] Invalid JSON response: " << responseData.constData() << std::endl;
        return QJsonObject();
    }
    return jsonDoc.object();
}

QJsonObject networkTests::performGetRequest(const QUrl& url, QUrlQuery& queryParams, int& httpStatusCode) {
    QUrl requestUrl(url);
    requestUrl.setQuery(queryParams);
    QNetworkRequest request(requestUrl);

    QNetworkReply *reply = networkManager->get(request);

    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec(); // Wait for the reply

    httpStatusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QByteArray responseData = reply->readAll();

    // Check for SSL errors if using HTTPS
    if (reply->error() != QNetworkReply::NoError) {
            std::cout << " [DEBUG] Network Error for GET " << requestUrl.toString().toStdString()
                      << ": " << reply->errorString().toStdString() << std::endl;
        }

    reply->deleteLater();

    if (responseData.isEmpty()) {
        std::cout << " [DEBUG] Empty response from server for GET " << url.toString().toStdString() << std::endl;
        return QJsonObject();
    }
    QJsonDocument jsonDoc = QJsonDocument::fromJson(responseData);
    if (jsonDoc.isNull() || !jsonDoc.isObject()) {
        std::cout << " [DEBUG] Invalid JSON response: " << responseData.constData() << std::endl;
        return QJsonObject();
    }
    return jsonDoc.object();
}

bool networkTests::testSuccessfulRegistration() {
    QUrl url(serverBaseUrl + "/auth/register");
    QJsonObject payload;
    payload["username"] = registeredUsername;
    payload["identityPublicKey"] = "dummyIdentityPubKeyBase64";
    payload["signedPreKeyPublicKey"] = "dummySignedPreKeyPubKeyBase64";
    payload["signedPreKeySignature"] = "dummySignedPreKeySigBase64";
    QJsonArray oneTimeKeys;
    oneTimeKeys.append("otk1_pub_base64");
    oneTimeKeys.append("otk2_pub_base64");
    payload["oneTimeKeys"] = oneTimeKeys;

    int statusCode = 0;
    QJsonObject response = performPostRequest(url, payload, statusCode);

    std::cout << " [Reg Status: " << statusCode << ", User: " << registeredUsername.toStdString() << "] ";
    return statusCode == 201 && response["status"].toString() == "success";
}

bool networkTests::testRegisterExistingUser() {
    QUrl url(serverBaseUrl + "/auth/register");
    QJsonObject payload;
    payload["username"] = registeredUsername;
    payload["identityPublicKey"] = "dummyIdentityPubKeyBase64_again";
    payload["signedPreKeyPublicKey"] = "dummySignedPreKeyPubKeyBase64_again";
    payload["signedPreKeySignature"] = "dummySignedPreKeySigBase64_again";
    QJsonArray oneTimeKeys;
    oneTimeKeys.append("otk3_pub_base64");
    payload["oneTimeKeys"] = oneTimeKeys;

    int statusCode = 0;
    QJsonObject response = performPostRequest(url, payload, statusCode);
    std::cout << " [ExistUser Status: " << statusCode << "] ";
    return statusCode == 400 && response["status"].toString() == "error" && response["message"].toString().contains("Username already exists");
}

bool networkTests::testChallengeRequestValidUser() {
    QUrl url(serverBaseUrl + "/auth/challenge");
    QUrlQuery query;
    query.addQueryItem("username", registeredUsername);

    int statusCode = 0;
    QJsonObject response = performGetRequest(url, query, statusCode);
    std::cout << " [ChalValid Status: " << statusCode << "] ";
    bool success = statusCode == 200 && response["status"].toString() == "success" && response.contains("nonce");
    if (success) {
        validNonceForLogin = response["nonce"].toString();
        std::cout << " [Nonce: " << validNonceForLogin.toStdString() << "] ";
    }
    return success;
}

bool networkTests::testChallengeRequestInvalidUser() {
    QUrl url(serverBaseUrl + "/auth/challenge");
    QUrlQuery query;
    query.addQueryItem("username", "nonexistentuser_" + QUuid::createUuid().toString(QUuid::Id128));

    int statusCode = 0;
    QJsonObject response = performGetRequest(url, query, statusCode);
    std::cout << " [ChalInvalid Status: " << statusCode << "] ";
    return statusCode == 404 && response["status"].toString() == "error";
}

bool networkTests::testLoginMissingFields() {
    QUrl url(serverBaseUrl + "/auth/login");
    QJsonObject payload;
    payload["username"] = registeredUsername;

    int statusCode = 0;
    QJsonObject response = performPostRequest(url, payload, statusCode);
    std::cout << " [LoginMissing Status: " << statusCode << "] ";
    return statusCode == 400 && response["status"].toString() == "error" && response["message"].toString().contains("Missing field");
}

bool networkTests::testLoginInvalidNonce() {
    QUrl url(serverBaseUrl + "/auth/login");
    QJsonObject payload;
    payload["username"] = registeredUsername;
    payload["nonce"] = "completely_fake_invalid_nonce_value_12345";
    payload["signature"] = "dummySignatureBase64";

    int statusCode = 0;
    QJsonObject response = performPostRequest(url, payload, statusCode);
    std::cout << " [LoginInvalidNonce Status: " << statusCode << "] ";
    return statusCode == 401 && response["status"].toString() == "error";
}


void networkTests::runAllNetworkTests(QNetworkAccessManager* manager) {
    std::cout << "\nStarting Network Request Test Suite" << std::endl;

    networkTests networkTests(manager);
    networkTests.runTests();
    networkTests.printSummary();

    const auto& results = networkTests.getResults();
    bool allPassed = true;
    for (const auto& result : results) {
        if (!result.passed) {
            allPassed = false;
            break;
        }
    }
    std::cout << "Overall Network Test result: " << (allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << std::endl;
}
