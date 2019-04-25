QT = core network

CONFIG += console
CONFIG -= app_bundle

HEADERS += \
    sshserver.h \
    sshsession.h

SOURCES += \
        main.cpp \
    sshserver.cpp \
    sshsession.cpp

RESOURCES += \
    keys.qrc
