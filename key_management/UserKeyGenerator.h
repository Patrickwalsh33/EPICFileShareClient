#ifndef USERKEYGENERATOR_H
#define USERKEYGENERATOR_H
#include <vector>
#include <stdexcept>

const size_t X25519_PUBLIC_KEY_SIZE = 32;
const size_t X25519_SECRET_KEY_SIZE = 32;

struct UserKeyPair
{
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> secret_key;

    UserKeyPair(): public_key(X25519_PUBLIC_KEY_SIZE), secret_key(X25519_SECRET_KEY_SIZE){}
};

class UserKeyGenerator
{
    public:
    UserKeyGenerator();

    UserKeyPair generateNewKeyPair();

};


#endif //USERKEYGENERATOR_H
