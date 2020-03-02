#ifndef ABSTRACTSSHOBJECT_H
#define ABSTRACTSSHOBJECT_H

struct ssh_bind_struct;
typedef struct ssh_bind_struct* ssh_bind;

class AbstractSshObject
{
protected:
    explicit AbstractSshObject(ssh_bind ssh);
    bool isError(int ret, const char *api) const;
public:
    virtual ~AbstractSshObject();
    ssh_bind ssh() const;

private:
    class Private;
    Private *d;
};

#endif // ABSTRACTSSHOBJECT_H
