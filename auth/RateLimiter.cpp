#include "RateLimiter.h"

RateLimiter::RateLimiter(){
    attempts = 0;
}

bool RateLimiter::canAttemptLogin(){
    QDateTime currentTime = QDateTime::currentDateTime();

    //if its been 5 minutes since the last attempt we can reset the counter
    if (lastAttemptTime.isValid() && lastAttemptTime.secsTo(currentTime) >= 300){
        attempts = 0;
    }


    if (attempts >= 5) { //if they fail login 5 times block login
        return false;
    }


    lastAttemptTime = currentTime; //update the last attempt time 
    attempts++; //update the attemps

    return true;

}

void RateLimiter::loginSuccess() { //reset everything if they succesfully log in
    attempts = 0;
    lastAttemptTime = QDateTime();
}



