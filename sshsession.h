#ifndef SSHSESSION_H
#define SSHSESSION_H

#include <QtCore/QIODevice>

struct WOLFSSH_CTX;

class SshSession : public QIODevice
{
    Q_OBJECT
public:
    explicit SshSession(WOLFSSH_CTX *ctx, qintptr socketDescriptor, QObject *parent = nullptr);
    ~SshSession() override;

    bool open(OpenMode mode) override;
    void close() override;

    qint64 bytesAvailable() const override;
    qint64 bytesToWrite() const override;

signals:
    void exec(const QByteArray &command);
    void shell();
    void errorOccurred();

protected:
    qint64 readData(char *data, qint64 maxlen) override;
    qint64 writeData(const char *data, qint64 len) override;

private:
    class Private;
    Private *d;
};

#endif // SSHSESSION_H