#include "SessionManager.h"
#include <QDebug> // For potential debugging

SessionManager* SessionManager::instance = nullptr;
// Our user of the Singleton design pattern for global access to session state across files

// Ensure the constructor matches the header (e.g., if it takes QObject* parent)
SessionManager::SessionManager(QObject *parent) 
    : QObject(parent), // Add if SessionManager now inherits QObject
      m_serverUrl("https://leftovers.gobbler.info") // Initialize server URL
{
    // Constructor logic, potentially loading tokens or username if persisted
    qDebug() << "SessionManager initialized. Server URL set to:" << m_serverUrl;
}

SessionManager::~SessionManager() {

    clearSessionData();
}

SessionManager* SessionManager::getInstance() {
    if (instance == nullptr) {

        // This a global singleton, often no parent is passed, and cleanupInstance is used.
        instance = new SessionManager(); 
    }
    return instance;
}

void SessionManager::cleanupInstance() {
    delete instance;
    instance = nullptr;
}


void SessionManager::setDecryptedKEK(const QByteArray& kek) {
    m_decryptedKEK = kek;
    qDebug() << "Decrypted KEK set in SessionManager.";
}

QByteArray SessionManager::getDecryptedKEK() const {
    return m_decryptedKEK;
}

// Implementations for individual token setters
void SessionManager::setAccessToken(const QByteArray& accessToken) {
    m_accessToken = accessToken;
    qDebug() << "Access Token set in SessionManager (individual setter).";
}

void SessionManager::setRefreshToken(const QByteArray& refreshToken) {
    m_refreshToken = refreshToken;
    qDebug() << "Refresh Token set in SessionManager (individual setter).";
}

QByteArray SessionManager::getAccessToken() const {
    return m_accessToken;
}

QByteArray SessionManager::getRefreshToken() const {
    return m_refreshToken;
}

void SessionManager::setTokens(const QByteArray& access, const QByteArray& refresh) {
    m_accessToken = access;
    m_refreshToken = refresh;
    qDebug() << "Access and Refresh Tokens set (via setTokens).";
}

void SessionManager::clearTokens() {
    m_accessToken.clear();
    m_refreshToken.clear();
    currentUsername.clear();
    qDebug() << "Tokens and username cleared.";

}

bool SessionManager::isLoggedIn() const {
    return !m_accessToken.isEmpty();
}

void SessionManager::setCurrentUsername(const QString& username) {
    currentUsername = username;
    qDebug() << "Current username set to:" << currentUsername;
}

QString SessionManager::getCurrentUsername() const {
    return currentUsername;
}


QString SessionManager::getServerUrl() const {
    return m_serverUrl;
}


void SessionManager::setServerUrl(const QString& url) {
    if (!url.isEmpty()) {
        m_serverUrl = url;
        qDebug() << "Server URL updated to:" << m_serverUrl;
    } else {
        qWarning() << "Attempted to set an empty server URL. Retaining previous URL:" << m_serverUrl;
    }
}

void SessionManager::clearSessionData() {
    // Securely clear the KEK
    if (!m_decryptedKEK.isEmpty()) {
        m_decryptedKEK.fill(0);
    }
    m_decryptedKEK.clear();


    m_accessToken.clear();
    m_refreshToken.clear();
    currentUsername.clear();
    qDebug() << "Full session data cleared (KEK, tokens, username).";
} 