#include <QtCore/QCoreApplication>

#include "sshserver.h"

int main(int argc, char *argv[])
{
    qSetMessagePattern("[%{time yyyyMMdd h:mm:ss.zzz t} %{if-debug}D%{endif}%{if-info}I%{endif}%{if-warning}W%{endif}%{if-critical}C%{endif}%{if-fatal}F%{endif}] %{function}:%{line} - %{message}");
    QCoreApplication app(argc, argv);

    SshServer server;

    return QCoreApplication::exec();
}
