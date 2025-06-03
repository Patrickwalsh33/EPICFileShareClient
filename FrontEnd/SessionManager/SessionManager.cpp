#include "SessionManager.h"

SessionManager* SessionManager::instance = nullptr;

SessionManager::SessionManager() {
    // Private constructor implementation
}

SessionManager::~SessionManager() {
    // Ensure sensitive data is cleared if not already
    clearSessionData();
}

SessionManager* SessionManager::getInstance() {
    if (!instance) {
        instance = new SessionManager();
    }
    return instance;
}

void SessionManager::cleanupInstance() {
    delete instance;
    instance = nullptr;
}

void SessionManager::setDecryptedKEK(const QByteArray& kek) {
    m_decryptedKEK = kek; // QByteArray creates a deep copy
}

QByteArray SessionManager::getDecryptedKEK() const {
    return m_decryptedKEK;
}
void SessionManager::setAccessToken(const QByteArray& accessToken)
{
    m_accessToken = accessToken;
}
QByteArray SessionManager::getAccessToken() const
{
    return m_accessToken;
}


void SessionManager::clearSessionData() {
    // Securely clear the KEK
    if (!m_decryptedKEK.isEmpty()) {
        m_decryptedKEK.fill(0); // Zero out the data
    }
    m_decryptedKEK.clear(); // Clear the byte array
} 