//
// Created by Tóla Bowen Maccurtain on 20/05/2025.
//

#ifndef PASSWORDHASHING_H
#define PASSWORDHASHING_H

#include <string>

class PasswordHashing {
public:
    PasswordHashing();
    ~PasswordHashing();

    std::string hashPassword(const std::string& password);
    bool verifyPassword(const std::string& hash, const std::string& password);
};

#endif // PASSWORD_HASHING_H

