#pragma once
#include <QDateTime>

class RateLimiter {
public:
    RateLimiter();

    bool canAttemptLogin(); //checks if login is allowed
    void loginSuccess();  //called when login succeeds

private:
    int attempts; //count of attemps
    QDateTime lastAttemptTime; //the time of the last attempt

};