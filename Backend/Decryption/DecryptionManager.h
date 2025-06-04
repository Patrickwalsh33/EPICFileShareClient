#ifndef DECRYPTIONMANAGER_H
#define DECRYPTIONMANAGER_H

#include <QByteArray>
#include <QString> // Added for return type
#include "../../X3DH/X3DH_shared.h" // Path relative to DecryptionManager.h
#include "../../crypto/crypto_utils.h" // Path relative to DecryptionManager.h

// Forward declaration to avoid circular dependency if ReceivedFileInfo is complex
// However, for simplicity, if ReceivedFileInfo is just a struct of simple types,
// including its header might be okay. Let's try including it directly.
#include "../../FrontEnd/RecievedFiles/recievedfilespage.h" // For ReceivedFileInfo struct

class DecryptionManager {
public:
    DecryptionManager();

    /**
     * @brief Derives the shared secret using X3DH and then derives the final symmetric key.
     * @param fileInfo Contains sender's public keys (ephemeral, identity).
     * @param receiverIdentityPrivEd Receiver's private Ed25519 identity key.
     * @param receiverSignedPrekeyPriv Receiver's private signed prekey (Curve25519).
     * @return The derived symmetric key for decryption, or an empty QByteArray on failure.
     */
    QByteArray deriveFileDecryptionKey(
        const ReceivedFileInfo& fileInfo,
        const QByteArray& receiverIdentityPrivEd,
        const QByteArray& receiverSignedPrekeyPriv
    );

    /**
     * @brief Decrypts the provided encrypted metadata using the given key and nonce.
     * @param encryptedMetadata The encrypted metadata blob.
     * @param metadataNonce The nonce used for encrypting the metadata.
     * @param decryptionKey The symmetric key (derived from X3DH) to use for decryption.
     * @return QString containing the decrypted JSON metadata, or an empty QString on failure.
     */
    QString decryptFileMetadata(
        const QByteArray& encryptedMetadata,
        const QByteArray& metadataNonce,
        const QByteArray& decryptionKey
    );

private:
    // If derive_key_from_shared_secret is not a free function and belongs to a class,
    // an instance of that class might be needed here, or it might be static.
    // Assuming it's a free function as per uploadpage.cpp usage pattern.
};

#endif // DECRYPTIONMANAGER_H 