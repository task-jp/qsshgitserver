#include "abstractsshobject.h"
#include <libssh/libssh.h>

#include <QtCore/QDebug>

class AbstractSshObject::Private
{
public:
    ssh_bind ssh;
};

AbstractSshObject::AbstractSshObject(ssh_bind ssh)
    : d(new Private{ssh})
{}

AbstractSshObject::~AbstractSshObject()
{
    delete d;
}

ssh_bind AbstractSshObject::ssh() const
{
    return d->ssh;
}

bool AbstractSshObject::isError(int ret, const char *api) const
{
    switch (ret) {
    case SSH_OK:
        break;
    case SSH_ERROR:
        qFatal("%s failed with %d: %s", api, ret, ssh_get_error(d->ssh));
    default:
        qFatal("%s failed with %d", api, ret);
    }
    return false;
}
