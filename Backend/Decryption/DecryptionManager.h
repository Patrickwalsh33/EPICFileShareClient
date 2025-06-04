#ifndef DECRYPTIONMANAGER_H
#define DECRYPTIONMANAGER_H

#include <QByteArray>
#include <QString> // Added for return type
#include "../../X3DH/X3DH_shared.h" // Path relative to DecryptionManager.h
#include "../../crypto/crypto_utils.h" // Path relative to DecryptionManager.h


#include "../../FrontEnd/RecievedFiles/recievedfilespage.h"

class DecryptionManager {
public:
    DecryptionManager();

    QByteArray deriveFileDecryptionKey(
        const ReceivedFileInfo& fileInfo,
        const QByteArray& receiverIdentityPrivEd,
        const QByteArray& receiverSignedPrekeyPriv
    );


    QString decryptFileMetadata(
        const QByteArray& encryptedMetadata,
        const QByteArray& metadataNonce,
        const QByteArray& decryptionKey
    );

    QByteArray decryptFileData(
        const QByteArray& encryptedData,
        const QByteArray& dek,
        const QByteArray& fileNonce
    );

private:

};

#endif // DECRYPTIONMANAGER_H 