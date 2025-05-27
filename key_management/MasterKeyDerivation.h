#pragma once
#include <string>
#include <vector>
#include <sodium.h>

class MasterKeyDerivation {
public:
    MasterKeyDerivation();
    ~MasterKeyDerivation();

    std::vector<unsigned char> deriveMaster(const std::string& password, const std::vector<unsigned char>& salt);
    bool verifyMaster(const std::string& hash, const std::string& password);
};