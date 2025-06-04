#include "DecryptionManager.h"
#include <sodium.h>
#include <iostream>
#include <vector>

DecryptionManager::DecryptionManager() {
    if (sodium_init() < 0) {
        std::cerr << "[DecryptionManager] libsodium initialization failed." << std::endl;

    }
}

QByteArray DecryptionManager::deriveFileDecryptionKey(
    const ReceivedFileInfo& fileInfo,
    const QByteArray& receiverIdentityPrivEd,
    const QByteArray& receiverSignedPrekeyPriv
) {
    if (fileInfo.senderEphemeralPublicKey.isEmpty() || 
        fileInfo.senderIdentityPublicKeyEd.isEmpty() || 
        receiverIdentityPrivEd.isEmpty() || 
        receiverSignedPrekeyPriv.isEmpty()) {
        std::cerr << "[DecryptionManager] deriveFileDecryptionKey: One or more required keys are empty." << std::endl;
        return QByteArray();
    }

    // Derive Shared Secret using X3DH receiver logic
    unsigned char sharedSecret[crypto_generichash_BYTES];

    bool x3dh_success = x3dh_receiver_derive_shared_secret(
        sharedSecret,
        sizeof(sharedSecret),
        reinterpret_cast<const unsigned char*>(fileInfo.senderEphemeralPublicKey.constData()),
        reinterpret_cast<const unsigned char*>(fileInfo.senderIdentityPublicKeyEd.constData()),
        reinterpret_cast<const unsigned char*>(receiverIdentityPrivEd.constData()),
        reinterpret_cast<const unsigned char*>(receiverSignedPrekeyPriv.constData())
    );

    if (!x3dh_success) {
        std::cerr << "[DecryptionManager] X3DH failed to derive shared secret." << std::endl;
        return QByteArray();
    }

    std::cout << "[DecryptionManager] X3DH shared secret derived successfully." << std::endl;

    //Derive the final key from the shared secret (mirroring sender's logic)
    unsigned char derivedKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    const char context[8] = "X3DHKEY"; // Same context as sender
    uint64_t subkey_id = 1;            // Same subkey_id as sender


    bool derivation_success = derive_key_from_shared_secret(
        sharedSecret,       // Input shared secret from X3DH
        derivedKey,         // Output buffer for the derived key
        context,            // Context string
        subkey_id           // Subkey identifier
    );

    if (!derivation_success) {
        std::cerr << "[DecryptionManager] Failed to derive final key from shared secret." << std::endl;
        return QByteArray();
    }

    std::cout << "[DecryptionManager] Final decryption key derived successfully." << std::endl;
    return QByteArray(reinterpret_cast<const char*>(derivedKey), sizeof(derivedKey));
}

QString DecryptionManager::decryptFileMetadata(
    const QByteArray& encryptedMetadata,
    const QByteArray& metadataNonce,
    const QByteArray& decryptionKey
) {
    if (encryptedMetadata.isEmpty()) {
        std::cerr << "[DecryptionManager] Encrypted metadata is empty." << std::endl;
        return QString();
    }
    if (metadataNonce.size() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        std::cerr << "[DecryptionManager] Invalid metadata nonce size. Expected " 
                  << crypto_aead_chacha20poly1305_ietf_NPUBBYTES 
                  << ", got " << metadataNonce.size() << std::endl;
        return QString();
    }
    if (decryptionKey.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        std::cerr << "[DecryptionManager] Invalid decryption key size. Expected " 
                  << crypto_aead_chacha20poly1305_ietf_KEYBYTES 
                  << ", got " << decryptionKey.size() << std::endl;
        return QString();
    }
    if (encryptedMetadata.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
        std::cerr << "[DecryptionManager] Encrypted metadata is too short to be valid (shorter than MAC size)." << std::endl;
        return QString();
    }

    std::vector<unsigned char> decryptedMessageBuffer(encryptedMetadata.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long decryptedMessageLen = 0;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decryptedMessageBuffer.data(), &decryptedMessageLen,
            nullptr, // nsec (not used in encryption, so nullptr here)
            reinterpret_cast<const unsigned char*>(encryptedMetadata.constData()),
            encryptedMetadata.size(),
            nullptr,
            0,
            reinterpret_cast<const unsigned char*>(metadataNonce.constData()),
            reinterpret_cast<const unsigned char*>(decryptionKey.constData())
        ) != 0) {
        std::cerr << "[DecryptionManager] crypto_aead_chacha20poly1305_ietf_decrypt failed. Message authentication tag mismatch or other error." << std::endl;
        return QString(); // Decryption failed (e.g., wrong key, tampered data, wrong nonce)
    }

    // Trim the buffer to the actual decrypted length
    decryptedMessageBuffer.resize(decryptedMessageLen);

    std::cout << "[DecryptionManager] File metadata decrypted successfully. Length: " << decryptedMessageLen << std::endl;
    return QString::fromUtf8(reinterpret_cast<const char*>(decryptedMessageBuffer.data()), decryptedMessageBuffer.size());
}

QByteArray DecryptionManager::decryptFileData(
    const QByteArray& encryptedData,
    const QByteArray& dek,
    const QByteArray& fileNonce)
{
    if (dek.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        qCritical() << "[DecryptionManager] Invalid DEK size for file data decryption.";
        return QByteArray();
    }
    if (fileNonce.size() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        qCritical() << "[DecryptionManager] Invalid nonce size for file data decryption.";
        return QByteArray();
    }
    if (encryptedData.isEmpty()) {
        qCritical() << "[DecryptionManager] Encrypted file data is empty.";
        return QByteArray();
    }

    std::vector<unsigned char> decrypted_data_vec(encryptedData.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long decrypted_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted_data_vec.data(), &decrypted_len,
            nullptr,
            reinterpret_cast<const unsigned char*>(encryptedData.constData()), encryptedData.size(),
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(fileNonce.constData()),
            reinterpret_cast<const unsigned char*>(dek.constData())
        ) != 0) {
        qWarning() << "[DecryptionManager] File data decryption failed (e.g., MAC mismatch).";
        return QByteArray();
    }

    decrypted_data_vec.resize(decrypted_len);
    return QByteArray(reinterpret_cast<const char*>(decrypted_data_vec.data()), decrypted_len);
} 