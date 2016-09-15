PKG_NAME=abe_relic
PKG_URL=ssh://gitolite@forge.ericsson.net/abe-icn/abe_relic.git
PKG_VERSION=145f1d51fe8a87ce64c79e8005296707831d491a
#4239e5074b35d14c0b54c8e098f351af6a102209
#

.PHONY: all

all: git-download 
	"$(MAKE)" -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libabe_relic.a ${BINDIR}/abe_relic.a

clean::
	@rm -rf $(BINDIR)$(PKG_NAME).a
	"$(MAKE)" -C $(PKG_BUILDDIR) clean
	
include $(RIOTBASE)/pkg/pkg.mk