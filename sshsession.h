#ifndef SSHSESSION_H
#define SSHSESSION_H

#include <QtCore/QIODevice>

class SshServer;

struct ssh_bind_struct;
typedef struct ssh_bind_struct* ssh_bind;

class SshSession : public QIODevice
{
    Q_OBJECT
public:
    explicit SshSession(ssh_bind ssh, SshServer *parent = nullptr);
    ~SshSession() override;

signals:
    void exec(const QByteArray &command);
    void shell();
    void errorOccurred();

public slots:
    void exit(int exit_status);

protected:
    qint64 readData(char *data, qint64 maxlen) override;
    qint64 writeData(const char *data, qint64 len) override;

private:
    class Private;
    Private *d;
};

#endif // SSHSESSION_H
