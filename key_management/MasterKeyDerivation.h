//
// Created by Tóla Bowen Maccurtain on 22/05/2025.
//

#ifndef MASTERKEYDERIVATION_H
#define MASTERKEYDERIVATION_H
#include <string>

class MasterKeyDerivation {
public:
    MasterKeyDerivation();
    ~MasterKeyDerivation();

    std::string deriveMaster(const std::string& password);
    bool verifyMaster(const std::string& hash, const std::string& password);
};

#endif //MASTERKEYDERIVATION_H
