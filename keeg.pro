#-------------------------------------------------
#
# Project created by QtCreator 2017-09-13T13:01:14
#
#-------------------------------------------------

QT       -= core gui

TARGET = keeg
TEMPLATE = lib
CONFIG += staticlib c++14

INCLUDEPATH += src $$(BOOST_ROOT)

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

DEFINES += FNV_USE_BOOST=1

SOURCES += \

HEADERS += \
    src/keeg/common/macrohelpers.hpp \
    src/keeg/common/enums.hpp \
    src/keeg/common/stringutils.hpp \
    src/keeg/common/stringencoding.hpp \
    src/keeg/endian/conversion.hpp \
    src/keeg/io/binaryreaders.hpp \
    src/keeg/io/binarywriters.hpp \
    src/keeg/io/binaryhelpers.hpp \
    src/keeg/hashing/hashalgorithm.hpp \
    src/keeg/hashing/keyedhashalgorithm.hpp \
    src/keeg/hashing/crc/crc32.hpp \
    src/keeg/hashing/crc/crc64.hpp \
    src/keeg/hashing/checksum/adler32.hpp \
    src/keeg/hashing/noncryptographic/aphash32.hpp \
    src/keeg/hashing/noncryptographic/bkdrhash32.hpp \
    src/keeg/hashing/noncryptographic/djb2hash32.hpp \
    src/keeg/hashing/noncryptographic/elfhash32.hpp \
    src/keeg/hashing/noncryptographic/fnv.hpp \
    src/keeg/hashing/noncryptographic/fnv1hash.hpp \
    src/keeg/hashing/noncryptographic/fnv1ahash.hpp \
    src/keeg/hashing/noncryptographic/joaathash32.hpp \
    src/keeg/hashing/noncryptographic/jshash32.hpp \
    src/keeg/hashing/noncryptographic/pjwhash32.hpp \
    src/keeg/hashing/noncryptographic/saxhash32.hpp \
    src/keeg/hashing/noncryptographic/sdbmhash32.hpp \
    src/keeg/hashing/noncryptographic/superfasthash32.hpp \
    src/keeg/hashing/noncryptographic/xxhash32.hpp \
    src/keeg/hashing/noncryptographic/xxhash64.hpp \
    src/keeg/hashing/cryptographic/md5.hpp \
    src/keeg/hashing/cryptographic/sha1.hpp \
    src/keeg/hashing/cryptographic/sha256.hpp \
    src/keeg/hashing/cryptographic/sha3.hpp

unix {
    target.path = /usr/lib
    INSTALLS += target
}

###############################
## COMPILER SCOPES
###############################

*msvc* {
        # So VCProj Filters do not flatten headers/source
        CONFIG -= flat

        # COMPILER FLAGS

        #  Optimization flags
        #QMAKE_CXXFLAGS_RELEASE -= /O2
        QMAKE_CXXFLAGS_RELEASE *= /O2 /Ot /Ox /GL
        #  Multithreaded compiling for Visual Studio
        QMAKE_CXXFLAGS += -MP
        # Linker flags
        QMAKE_LFLAGS_RELEASE += /LTCG
}

*-g++ {

        # COMPILER FLAGS

        #  Optimization flags
        QMAKE_CXXFLAGS_DEBUG -= -O0 -g
        QMAKE_CXXFLAGS_DEBUG += -Og -g3 -std=c++14
        #QMAKE_CXXFLAGS_DEBUG += -static-libgcc -static-libstdc++
        QMAKE_CXXFLAGS_RELEASE += -O3 -mfpmath=sse

        # C++14 Support
        QMAKE_CXXFLAGS_RELEASE += -std=c++14

        #  Extension flags
        QMAKE_CXXFLAGS_RELEASE += -msse2 -msse
        QMAKE_LFLAGS_RELEASE += -static #-static-libgcc -static-libstdc++
}
