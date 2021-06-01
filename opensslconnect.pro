TEMPLATE = app
CONFIG += console c++1z c++2a
CONFIG -= app_bundle
CONFIG -= qt
LIBS+=-lssl -lcrypto

SOURCES += \
        main.cpp
