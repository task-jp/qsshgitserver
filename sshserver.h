#ifndef SSHSERVER_H
#define SSHSERVER_H

#include <QtNetwork/QTcpServer>

class SshServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit SshServer(QObject *parent = nullptr);
    ~SshServer() override;

public slots:
signals:

protected:
    void incomingConnection(qintptr socketDescriptor) override;

private:
    class Private;
    Private *d;
};

#endif // SSHSERVER_H