PKG_NAME=abe_relic
PKG_URL=ssh://gitolite@forge.ericsson.net/abe-icn/abe_relic.git
PKG_VERSION=b015aabd606c573b849f3edf3146169f717d2632


.PHONY: all

all: git-download 
	"$(MAKE)" -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libabe_relic.a ${BINDIR}/abe_relic.a

clean::
	@rm -rf $(BINDIR)$(PKG_NAME).a
	"$(MAKE)" -C $(PKG_BUILDDIR) clean
	
include $(RIOTBASE)/pkg/pkg.mk