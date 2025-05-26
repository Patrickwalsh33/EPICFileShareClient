//
// Created by Andrew Jaffray on 26/05/2025.
//

#ifndef MYQTAPP_UPLOADMANAGER_H
#define MYQTAPP_UPLOADMANAGER_H
#pragma once

#include <QObject>
#include <QString>


class uploadManager : public QObject
{
    Q_OBJECT

public:
    explicit uploadManager(QObject *parent = nullptr);
    ~uploadManager();

    bool uploadFile(const QString &filePath);

signals:
    void uploadSucceeded();
    void uploadFailed(const QString &error);


};

#endif //MYQTAPP_UPLOADMANAGER_H
