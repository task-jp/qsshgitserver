#include "sshsession.h"
#include "sshserver.h"
#include "abstractsshobject.h"

#include <QtCore/QDebug>
#include <QtCore/QSocketNotifier>

#include <libssh/libssh.h>
#include <libssh/server.h>

class SshSession::Private : public AbstractSshObject
{
public:
    Private(ssh_bind ssh, SshSession *parent);
    ~Private() override;

    void exit(int exit_status);
private:
    bool read();

private:
    SshSession *q;
    QSocketNotifier *socketNotifier;
    ssh_session session;
public:
    ssh_channel channel;
};

SshSession::Private::Private(ssh_bind ssh, SshSession *parent)
    : AbstractSshObject(ssh)
    , q(parent)
    , socketNotifier(nullptr)
    , session(ssh_new())
    , channel(nullptr)
{
    if (isError(ssh_bind_accept(ssh, session), "ssh_bind_accept"))
        return;

    ssh_set_blocking(session, 0);
    ssh_handle_key_exchange(session);

    socketNotifier = new QSocketNotifier(ssh_get_fd(session), QSocketNotifier::Read, q);
    QMetaObject::Connection connection;
    connection = connect(socketNotifier, &QSocketNotifier::activated, [connection, this]() {
        if (!read()) {
            disconnect(connection);
        } else {
            connect(socketNotifier, &QSocketNotifier::activated, q, &QIODevice::readyRead);
        }
    });
}

void SshSession::Private::exit(int exit_status)
{
    ssh_set_blocking(session, 1);

    if (isError(ssh_channel_request_send_exit_status(channel, exit_status), "ssh_channel_request_send_exit_status"))
        return;

    if (isError(ssh_channel_send_eof(channel), "ssh_channel_send_eof"))
        return;

    if (isError(ssh_channel_close(channel), "ssh_channel_close"))
        return;

    qDebug() << q->readAll();
    ssh_channel_free(channel);
    isError(ssh_blocking_flush(session, -1), "ssh_blocking_flush");
    q->deleteLater();
}

bool SshSession::Private::read()
{
    bool ret = true;
    while (true) {
        ssh_message message = ssh_message_get(session);
        if (!message) {
            break;
        }
        int type = ssh_message_type(message);
        int subtype = ssh_message_subtype(message);
        bool replied = false;
        switch (type) {
        case SSH_REQUEST_AUTH:
            switch (subtype) {
            case SSH_AUTH_METHOD_PASSWORD: {
                auto user = ssh_message_auth_user(message);
                auto pass = ssh_message_auth_password(message);
                if (qobject_cast<SshServer *>(q->parent())->authPassword(user, pass)) {
                    ssh_message_auth_reply_success(message, 0);
                    replied = true;
                }
                break; }
            case SSH_AUTH_METHOD_PUBLICKEY: {
                auto key = ssh_message_auth_pubkey(message);
                if (qobject_cast<SshServer *>(q->parent())->authPublicKey(key)) {
                    ssh_message_auth_reply_success(message, 0);
                    replied = true;
                }
                break; }
            default:
                qWarning() << "SSH_REQUEST_AUTH: subtype" << subtype << "not handled";
                break;
            }
            if (!replied) {
                ssh_message_auth_set_methods(message,
                                             SSH_AUTH_METHOD_PASSWORD |
                                             SSH_AUTH_METHOD_PUBLICKEY);
            }
            break;
        case SSH_REQUEST_CHANNEL_OPEN:
            switch (subtype) {
            case SSH_CHANNEL_SESSION:
                channel = ssh_message_channel_request_open_reply_accept(message);
                replied = true;
                break;
            default:
                qWarning() << "SSH_REQUEST_CHANNEL_OPEN: subtype" << subtype << "not handled";
                break;
            }
            break;
        case SSH_REQUEST_CHANNEL:
            switch (subtype) {
            case SSH_CHANNEL_REQUEST_SHELL:
                ssh_message_channel_request_reply_success(message);
                replied = true;
                emit q->shell();
                ret = false;
                break;
            case SSH_CHANNEL_REQUEST_EXEC: {
                QByteArray command(ssh_message_channel_request_command(message));
                replied = true;
                emit q->exec(command);
                ret = false;
                break; }
            default:
                qWarning() << "SSH_REQUEST_CHANNEL: subtype" << subtype << "not handled";
                break;
            }
            break;
        default:
            qDebug() << type << subtype;
            break;
        }

        if (!replied) {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }
    return ret;
}

SshSession::Private::~Private()
{
    qDebug() << q;
    ssh_disconnect(session);
    ssh_free(session);
}

SshSession::SshSession(ssh_bind ssh, SshServer *parent)
    : QIODevice(parent)
    , d(new Private(ssh, this))
{
    open(ReadWrite);
}

SshSession::~SshSession()
{
    close();
    delete d;
}

qint64 SshSession::readData(char *data, qint64 maxlen)
{
    auto ret = ssh_channel_read(d->channel, data, maxlen, 0);
//    qDebug() << ret;
    return ret;
}

qint64 SshSession::writeData(const char *data, qint64 len)
{
    auto ret = ssh_channel_write(d->channel, data, len);
//    qDebug() << len << ret;
    return ret;
}

void SshSession::exit(int exit_status)
{
    d->exit(exit_status);
}
