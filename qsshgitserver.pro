QT = core network

CONFIG += cmdline

HEADERS += \
    abstractsshobject.h \
    sshserver.h \
    sshsession.h

SOURCES += \
    abstractsshobject.cpp \
        main.cpp \
    sshserver.cpp \
    sshsession.cpp

LIBS += -lssh
