#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include <QByteArray>

class SessionManager {
private:
    static SessionManager* instance;
    QByteArray m_decryptedKEK;

    SessionManager(); // Private constructor
    ~SessionManager(); // Private destructor

public:
    SessionManager(const SessionManager&) = delete; // No copy constructor
    SessionManager& operator=(const SessionManager&) = delete; // No copy assignment

    static SessionManager* getInstance();
    static void cleanupInstance(); // Call at application exit

    void setDecryptedKEK(const QByteArray& kek);
    QByteArray getDecryptedKEK() const;

    void clearSessionData(); // Call on logout
};

#endif // SESSIONMANAGER_H 