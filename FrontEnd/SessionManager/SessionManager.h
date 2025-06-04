#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include <QByteArray>
#include <QString>
#include <QObject>

class SessionManager : public QObject
{
    Q_OBJECT
private:
    static SessionManager* instance;
    QByteArray m_decryptedKEK;
    QByteArray m_accessToken;
    QByteArray m_refreshToken;
    QString currentUsername;
    QString m_serverUrl;

    SessionManager(QObject *parent = nullptr); // Private constructor
    ~SessionManager(); // Private destructor

public:
    SessionManager(const SessionManager&) = delete; // No copy constructor
    SessionManager& operator=(const SessionManager&) = delete; // No copy assignment

    static SessionManager* getInstance();
    static void cleanupInstance(); // Call at application exit

    void setDecryptedKEK(const QByteArray& kek);
    QByteArray getDecryptedKEK() const;

    void setAccessToken(const QByteArray& accessToken);
    QByteArray getAccessToken() const;

    void setRefreshToken(const QByteArray& refreshToken);
    QByteArray getRefreshToken() const;

    void clearSessionData(); // Call on logout

    void setCurrentUsername(const QString& username);
    QString getCurrentUsername() const;

    QString getServerUrl() const;
    void setServerUrl(const QString& url);

    bool isLoggedIn() const;

    void setTokens(const QByteArray& access, const QByteArray& refresh);
    void clearTokens();
};

#endif // SESSIONMANAGER_H 