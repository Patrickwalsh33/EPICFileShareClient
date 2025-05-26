#pragma once
#include <string>

class MasterKeyDerivation {
public:
    MasterKeyDerivation();
    ~MasterKeyDerivation();

    std::string deriveMaster(const std::string& password);
    bool verifyMaster(const std::string& hash, const std::string& password);
};