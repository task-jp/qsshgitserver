#include "sshserver.h"
#include "abstractsshobject.h"
#include "sshsession.h"

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QPointer>
#include <QtCore/QProcess>
#include <QtCore/QSocketNotifier>

#include <libssh/libssh.h>
#include <libssh/server.h>

class SshServer::Private : public AbstractSshObject
{
public:
    Private(SshServer *parent);
    ~Private();

    void appendPublicKey(const QByteArray &data);

    void git(SshSession *session, const QString &program, const QStringList &args);

    QString toProject(const QString &data) const
    {
        QString ret = data;
        if (ret.startsWith(QLatin1Char('\''))) {
            ret = ret.mid(1);
        }
        if (ret.endsWith(QLatin1Char('\''))) {
            ret.chop(1);
        }
        if (ret.startsWith(QLatin1Char('/'))) {
            ret = ret.mid(1);
        }
        return ret;
    }

private:
    SshServer *q;
public:
    QSocketNotifier *socketNotifier;
    QList<ssh_key> publicKeys;
};

SshServer::Private::Private(SshServer *parent)
    : AbstractSshObject(ssh_bind_new())
    , q(parent)
    , socketNotifier(nullptr)
{
    if (qEnvironmentVariableIsSet("PUBLIC_KEY")) {
        appendPublicKey(qEnvironmentVariable("PUBLIC_KEY").toUtf8());
    } else {
        qWarning("set environment variable PUBLIC_KEY=\"ssh-rsa AAA...AAA tasuku@aaa\"");
    }

    ssh_bind_options_set(ssh(), SSH_BIND_OPTIONS_BINDPORT_STR, "22222");
    if (QFile::exists(QStringLiteral("ssh_host_dsa_key")))
        ssh_bind_options_set(ssh(), SSH_BIND_OPTIONS_DSAKEY, "ssh_host_dsa_key");
    if (QFile::exists(QStringLiteral("ssh_host_rsa_key")))
        ssh_bind_options_set(ssh(), SSH_BIND_OPTIONS_RSAKEY, "ssh_host_rsa_key");

    ssh_bind_set_blocking(ssh(), 0);

    int ret = ssh_bind_listen(ssh());
    if (isError(ret, "ssh_bind_listen"))
        return;

    socketNotifier = new QSocketNotifier(ssh_bind_get_fd(ssh()), QSocketNotifier::Read, q);
    connect(socketNotifier, &QSocketNotifier::activated, [this]() {
        qDebug() << "new session";
        auto session = new SshSession(ssh(), q);
        connect(session, &SshSession::errorOccurred, [session]() {
            session->deleteLater();
        });
        connect(session, &SshSession::exec, [this, session](const QByteArray &command) {
            qDebug() << command;
            QStringList args = QString::fromUtf8(command).split(QLatin1Char(' '));
            if (args.length() == 2) {
                const QString &program = args.at(0);
                QString project = toProject(args.at(1));
                if (program == QStringLiteral("git-upload-pack")) {
                    git(session, program, {project});
                    return;
                }
                if (program == QStringLiteral("git-receive-pack")) {
                    git(session, program, {project});
                    return;
                }
            }
            session->write(QStringLiteral("%1 command not supporeted.\n").arg(QString::fromUtf8(command)).toUtf8());
            session->deleteLater();
        });

        connect(session, &SshSession::shell, [session]() {
            session->write("Bye\n");
            session->exit(0);
        });
    });
}

SshServer::Private::~Private()
{
    ssh_bind_free(ssh());
}

void SshServer::Private::appendPublicKey(const QByteArray &data)
{
    QByteArrayList array = data.split(' ');
    if (array.length() == 3) {
        ssh_key key;
        auto type = array.at(0);
        auto username = array.at(2);
        int at = username.indexOf('@');
        if (at > 0)
            username = username.left(at);
        if (!isError(ssh_pki_import_pubkey_base64(array.at(1).constData(), ssh_key_type_from_name(type.constData()), &key), "ssh_pki_import_pubkey_base64")) {
            publicKeys.append(key);
        }
    }
}

void SshServer::Private::git(SshSession *session, const QString &program, const QStringList &args)
{
    QPointer<QProcess> git(new QProcess(q));
    git->setObjectName("git");

    connect(git, &QProcess::readyReadStandardOutput, [session, git]() {
//        qDebug() << git << session;
        QByteArray data = git->readAllStandardOutput();
//        qDebug() << (data.length() > 10 ? data.left(10) : data).toHex();
        session->write(data);
    });
    connect(git, &QProcess::readyReadStandardError, [git]() {
        QByteArray data = git->readAllStandardError();
        qWarning() << data;
    });
    connect(git, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), [session, git]() mutable {
        qDebug() << git->program() << git->arguments() << git->exitStatus() << git->exitCode();
        git->deleteLater();
        session->exit(git->exitCode());
    });
    connect(session, &SshSession::readyRead, [git, session]() {
        QByteArray data = session->readAll();
//        qDebug() << (data.length() > 10 ? data.left(10) : data).toHex();
        if (git && !data.isEmpty()) {
//            qDebug() << git << session;
            git->write(data);
        }
    });
    git->start(program, args);
}

SshServer::SshServer(QObject *parent)
    : QObject(parent)
    , d(new Private(this))
{
}

SshServer::~SshServer()
{
    delete d;
}

bool SshServer::authPassword(const char *user, const char *password) const
{
    qDebug() << "User" << user << "/" << password;
    return qstrcmp(user, "git") == 0;
}

bool SshServer::authPublicKey(ssh_key key) const
{
    for (const auto &k : d->publicKeys) {
        if (ssh_key_cmp(k, key, SSH_KEY_CMP_PUBLIC))
            return true;
    }
    return false;
}
