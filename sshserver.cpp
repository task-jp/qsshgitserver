#include "sshserver.h"
#include "sshsession.h"

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QProcess>

#include <wolfssh/ssh.h>

class SshServer::Private
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
    WOLFSSH_CTX *ctx;
    struct PublicKey {
        QByteArray type;
        QByteArray value;
    };
    QMultiMap<QByteArray, PublicKey> publicKeys;
};

SshServer::Private::Private(SshServer *parent)
    : q(parent)
    , ctx(nullptr)
{
    if (qEnvironmentVariableIsSet("PUBLIC_KEY")) {
        appendPublicKey(qEnvironmentVariable("PUBLIC_KEY").toUtf8());
    } else {
        qFatal("set environment variable PUBLIC_KEY=\"ssh-rsa AAA...AAA tasuku@aaa\"");
    }

    wolfSSH_Debugging_ON();
    if (wolfSSH_Init() != WS_SUCCESS) {
        qFatal("wolfSSH_Init failed.");
    }
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, nullptr);
    if (!ctx) {
        qFatal("wolfSSH_CTX_new failed");
    }

    wolfSSH_SetUserAuth(ctx, [](byte authType, WS_UserAuthData* authData, void* ctx) ->int {
        if (authType != WOLFSSH_USERAUTH_PUBLICKEY) {
            return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
        }

        SshServer::Private *d = static_cast<SshServer *>(ctx)->d;
        QByteArray authName(reinterpret_cast<const char *>(authData->authName), authData->authNameSz);
        QByteArray username(reinterpret_cast<const char *>(authData->username), authData->usernameSz);
        QByteArray serviceName(reinterpret_cast<const char *>(authData->serviceName), authData->serviceNameSz);
        qDebug() << authType << authName << username << serviceName << ctx;

        if (!d->publicKeys.contains(username)) {
            return WOLFSSH_USERAUTH_INVALID_USER;
        }

        PublicKey key;
        key.type = QByteArray(reinterpret_cast<const char *>(authData->sf.publicKey.publicKeyType), authData->sf.publicKey.publicKeyTypeSz);
        key.value = QByteArray(reinterpret_cast<const char *>(authData->sf.publicKey.publicKey), authData->sf.publicKey.publicKeySz);

        for (const PublicKey &k : d->publicKeys.values(username)) {
            if (k.type == key.type && k.value == key.value) {
                qInfo() << username << "found";
                return WOLFSSH_USERAUTH_SUCCESS;
            }
        }

        return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
    });


    QByteArray key;
    QFile file(qEnvironmentVariable("SERVER_KEY_DER", QStringLiteral(":/server-key-rsa.der")));
    file.open(QFile::ReadOnly);
    key = file.readAll();
    file.close();
    int ret = wolfSSH_CTX_UsePrivateKey_buffer(ctx, reinterpret_cast<const byte *>(key.constData()), key.length(), WOLFSSH_FORMAT_ASN1);
    if (ret != WS_SUCCESS) {
        qFatal("wolfSSH_CTX_UsePrivateKey_buffer failed");
    }

    if (qEnvironmentVariableIsSet("SERVER_BANNER")) {
        ret = wolfSSH_CTX_SetBanner(ctx, qUtf8Printable(qEnvironmentVariable("SERVER_BANNER")));
        if (ret != WS_SUCCESS) {
            qFatal("wolfSSH_CTX_SetBanner failed");
        }
    }
}

SshServer::Private::~Private()
{
    if (ctx) {
        wolfSSH_CTX_free(ctx);
    }
    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        qFatal("wolfSSH_Cleanup failed.");
    }
    wolfSSH_Debugging_OFF();
}

void SshServer::Private::appendPublicKey(const QByteArray &data)
{
    PublicKey key;
    QByteArrayList array = data.split(' ');
    if (array.length() == 3) {
        key.type = array.at(0);
        key.value = QByteArray::fromBase64(array.at(1));
        QByteArray username = array.at(2);
        int at = username.indexOf('@');
        if (at > 0)
            username = username.left(at);
        publicKeys.insert(username, key);
    }
}

void SshServer::Private::git(SshSession *session, const QString &program, const QStringList &args)
{
    auto git = new QProcess(q);
    git->setObjectName("git");
    connect(git, &QProcess::destroyed, session, &SshSession::deleteLater);

    connect(git, &QProcess::readyReadStandardOutput, [session, git]() {
        QByteArray data = git->readAllStandardOutput();
//        qDebug() << data;
        session->write(data);
    });
    connect(git, &QProcess::readyReadStandardError, [git]() {
        QByteArray data = git->readAllStandardError();
        qWarning() << data;
    });
    connect(git, QOverload<int>::of(&QProcess::finished), [git]() {
        qDebug() << git->program() << git->arguments() << git->exitStatus() << git->exitCode();
        git->deleteLater();
    });
    connect(session, &SshSession::readyRead, [git, session]() {
        QByteArray data = session->readAll();
//        qDebug() << (data.length() > 10 ? data.left(10) : data);
        git->write(data);
    });
    git->start(program, args);
}

SshServer::SshServer(QObject *parent)
    : QTcpServer(parent)
    , d(new Private(this))
{
}

SshServer::~SshServer()
{
    delete d;
}

void SshServer::incomingConnection(qintptr socketDescriptor)
{
    qInfo() << "new session started at" << socketDescriptor;

    auto session = new SshSession(d->ctx, socketDescriptor, this);
    session->setObjectName("ssh");

    connect(session, &SshSession::errorOccurred, [session]() {
        session->deleteLater();
    });
    connect(session, &SshSession::exec, [this, session](const QByteArray &command) {
        qDebug() << command;
        QStringList args = QString::fromUtf8(command).split(QLatin1Char(' '));
        if (args.length() == 2) {
            const QString &program = args.at(0);
            QString project = d->toProject(args.at(1));
            if (program == QStringLiteral("git-upload-pack")) {
                d->git(session, program, {project});
                return;
            }
            if (program == QStringLiteral("git-receive-pack")) {
                d->git(session, program, {project});
                return;
            }
        }
        session->write(QStringLiteral("%1 command not supporeted.\n").arg(QString::fromUtf8(command)).toUtf8());
        session->deleteLater();
        delete session;
    });

    connect(session, &SshSession::shell, [session]() {
        session->write("Bye\n");
        session->deleteLater();
        delete session;
    });
}
