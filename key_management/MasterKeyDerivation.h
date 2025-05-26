#ifndef MASTERKEYDERIVATION_H
#define MASTERKEYDERIVATION_H
#include <string>

class MasterKeyDerivation {
public:
    MasterKeyDerivation();
    ~MasterKeyDerivation();

    std::vector<unsigned char> deriveMaster(const std::string& password, const std::vector<unsigned char>& salt);
    bool verifyMaster(const std::string& hash, const std::string& password);
};

#endif //MASTERKEYDERIVATION_H
