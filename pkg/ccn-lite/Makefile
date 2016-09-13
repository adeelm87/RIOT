PKG_NAME=ccn-lite
PKG_URL=ssh://gitolite@forge.ericsson.net/abe-icn/ccn-lite.git
PKG_VERSION=be48b5b109ab61991aa1dfb5c40f5fdd4c8acc20

.PHONY: all

export RIOT_CFLAGS = ${CFLAGS} ${INCLUDES}

all: git-download
	"$(MAKE)" -BC $(PKG_BUILDDIR)/src lib-ccn-lite.a
	"$(MAKE)" -BC $(PKG_BUILDDIR)/src lib-ccn-lite-utils.a
	cp $(PKG_BUILDDIR)/src/lib-ccn-lite.a ${BINDIR}/ccn-lite.a
	cp $(PKG_BUILDDIR)/src/lib-ccn-lite-utils.a ${BINDIR}/ccn-lite-utils.a

include $(RIOTBASE)/pkg/pkg.mk
