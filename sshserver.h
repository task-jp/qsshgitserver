#ifndef SSHSERVER_H
#define SSHSERVER_H

#include <QtCore/QObject>

class SshSession;

struct ssh_key_struct;
typedef struct ssh_key_struct* ssh_key;

class SshServer : public QObject
{
    Q_OBJECT
public:
    explicit SshServer(QObject *parent = nullptr);
    ~SshServer() override;

    bool authPassword(const char *user, const char *password) const;
    bool authPublicKey(ssh_key key) const;

private:
    class Private;
    Private *d;
};

#endif // SSHSERVER_H
