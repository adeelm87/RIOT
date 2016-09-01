PKG_NAME=ccn-lite
PKG_URL=ssh://gitolite@forge.ericsson.net/abe-icn/ccn-lite.git
<<<<<<< HEAD
PKG_VERSION=9b2d0253466adae2c8288a6fa0a8f0fa0a9b096b
=======
PKG_VERSION=421451196b06de8f9bded57f2ba183ffd8fad892
>>>>>>> ccn-gw-eth-802154-noip

.PHONY: all

export RIOT_CFLAGS = ${CFLAGS} ${INCLUDES}

all: git-download
	"$(MAKE)" -BC $(PKG_BUILDDIR)/src lib-ccn-lite.a
	"$(MAKE)" -BC $(PKG_BUILDDIR)/src lib-ccn-lite-utils.a
	cp $(PKG_BUILDDIR)/src/lib-ccn-lite.a ${BINDIR}/ccn-lite.a
	cp $(PKG_BUILDDIR)/src/lib-ccn-lite-utils.a ${BINDIR}/ccn-lite-utils.a

include $(RIOTBASE)/pkg/pkg.mk
