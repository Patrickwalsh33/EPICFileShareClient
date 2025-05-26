#include "EncryptionKeyGenerator.h"
#include <vector>
#include <sodium/randombytes.h>

std::vector<unsigned char> EncryptionKeyGenerator::generateKey(size_t num_bytes)
{
    if (num_bytes == 0) {
        return {}; // Return empty vector for 0 bytes requested
    }

    std::vector<unsigned char> buffer(num_bytes);

    randombytes_buf(buffer.data(), num_bytes);
    return buffer;
}