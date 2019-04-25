#include "sshsession.h"

#include <QtCore/QDebug>
#include <QtCore/QSocketNotifier>

#include <wolfssh/ssh.h>

class SshSession::Private
{
public:
    Private(WOLFSSH_CTX *ctx, qintptr socketDescriptor, SshSession *parent);

    bool open(OpenMode openMode);
    void close();
    void read();
    void write();

private:
    void accept();

private:
    SshSession *q;

public:
    WOLFSSH_CTX *ctx;
    int socketDescriptor;
    WOLFSSH *ssh;
    QSocketNotifier readNotifier;
    QByteArray input;
    QSocketNotifier writeNotifier;
    QByteArray output;
    bool accepted;
};

SshSession::Private::Private(WOLFSSH_CTX *ctx, qintptr socketDescriptor, SshSession *parent)
    : q(parent)
    , ctx(ctx)
    , socketDescriptor(static_cast<int>(socketDescriptor))
    , ssh(nullptr)
    , readNotifier(socketDescriptor, QSocketNotifier::Read)
    , writeNotifier(socketDescriptor, QSocketNotifier::Write)
    , accepted(false)
{
    readNotifier.setEnabled(false);
    connect(&readNotifier, &QSocketNotifier::activated, [this]() { read(); });
    writeNotifier.setEnabled(false);
    connect(&writeNotifier, &QSocketNotifier::activated, [this]() { write(); });
}

bool SshSession::Private::open(SshSession::OpenMode openMode)
{
    if (!ctx)
        return false;
    ssh = wolfSSH_new(ctx);

    if (!ssh) {
        qWarning("wolfSSH_new failed");
        return false;
    }
    int ret = wolfSSH_set_fd(ssh, (int)socketDescriptor);
    if (ret != WS_SUCCESS) {
        qWarning("wolfSSH_set_fd failed");
        wolfSSH_free(ssh);
        return false;
    }
    wolfSSH_SetUserAuthCtx(ssh, q->parent());

    readNotifier.setEnabled(openMode & ReadOnly);
    writeNotifier.setEnabled(openMode & WriteOnly);
    return true;
}

void SshSession::Private::close()
{
    if (!ssh)
        return;

    int ret = wolfSSH_stream_exit(ssh, 0);
    if (ret != WS_SUCCESS) {
        qWarning("wolfSSH_stream_exit failed");
    }

    ::close(socketDescriptor);
    wolfSSH_free(ssh);
    ssh = nullptr;
}

void SshSession::Private::read()
{
    if (!accepted) {
        accept();
        return;
    }
    char buffer[32768];
    int size = input.length();
    bool eof = false;
    while (!eof) {
        int ret = wolfSSH_stream_read(ssh, reinterpret_cast<byte *>(buffer), sizeof(buffer));
        if (ret > 0) {
            input.append(buffer, ret);
        } else {
            int error = wolfSSH_get_error(ssh);
            switch (ret) {
            case WS_SUCCESS:
                break;
            case WS_FATAL_ERROR:
                switch (error) {
                case WS_WANT_READ:
                    break;
                case WS_SOCKET_ERROR_E:
                    qDebug() << wolfSSH_get_error_name(ssh);
                    emit q->errorOccurred();
                    break;
                default:
                    qWarning() << error;
                }
                break;
            case WS_EOF:
                switch (error) {
                case WS_WANT_READ:
                    break;
                case WS_SOCKET_ERROR_E:
                    qDebug() << wolfSSH_get_error_name(ssh);
                    emit q->errorOccurred();
                    break;
                default:
                    qWarning() << error << wolfSSH_get_error_name(ssh);
                    eof = true;
                }
                break;
            default:
                qWarning() << ret << "not handled";
                break;
            }
            break;
        }
    }
    if (size < input.length()) {
//        qDebug() << input;
        emit q->readyRead();
    }
}

void SshSession::Private::accept()
{
    accepted = (wolfSSH_accept(ssh) == WS_SUCCESS);

    if (accepted) {
        switch (wolfSSH_GetSessionType(ssh)) {
        case WOLFSSH_SESSION_EXEC:
            emit q->exec(QByteArray(wolfSSH_GetSessionCommand(ssh)));
            break;
        case WOLFSSH_SESSION_SHELL:
            emit q->shell();
            break;
        default:
            qWarning("wolfSSH_GetSessionType() %d not suported", wolfSSH_GetSessionType(ssh));
            emit q->errorOccurred();
            break;
        }
    }
}
void SshSession::Private::write()
{
    int written = 0;
    byte *data = reinterpret_cast<byte *>(output.data());
    word32 len = output.length();
    while (len != written) {
//        qDebug() << output;
        int ret = wolfSSH_stream_send(ssh, data + written, len - written);
        if (ret > 0) {
            written += ret;
        } else {
            int error = wolfSSH_get_error(ssh);
            switch (ret) {
            case WS_SUCCESS:
                break;
            case WS_FATAL_ERROR:
                switch (error) {
                case WS_WANT_WRITE:
                    break;
                default:
                    qWarning() << error;
                }
                break;
            case WS_EOF:
                qFatal("WF_EOF");
                break;
            default:
                qWarning() << ret << "not handled";
                break;
            }
            break;
        }
    }
    if (written > 0) {
        output = output.mid(written);
//        qDebug() << output;
        emit q->bytesWritten(written);
    }
}

SshSession::SshSession(WOLFSSH_CTX *ctx, qintptr socketDescriptor, QObject *parent)
    : QIODevice(parent)
    , d(new Private(ctx, socketDescriptor, this))
{
    open(ReadWrite);
}

SshSession::~SshSession()
{
    close();
    delete d;
}

bool SshSession::open(SshSession::OpenMode mode)
{
    if (!d->open(mode)) {
        return false;
    }
    return QIODevice::open(mode);
}

void SshSession::close()
{
    d->close();
    QIODevice::close();
}

qint64 SshSession::bytesAvailable() const
{
    return d->input.length();
}

qint64 SshSession::bytesToWrite() const
{
    return d->output.length();
}

qint64 SshSession::readData(char *data, qint64 maxlen)
{
    d->read();
    qint64 ret = std::min<qint64>(d->input.length(), maxlen);
    memcpy(data, d->input.constData(), ret);
    d->input = d->input.mid(ret);
    return ret;
}

qint64 SshSession::writeData(const char *data, qint64 len)
{
    d->output.append(data, len);
    d->write();
    return len;
}
