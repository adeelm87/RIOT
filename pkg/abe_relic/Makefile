PKG_NAME=abe_relic
PKG_URL=ssh://gitolite@forge.ericsson.net/abe-icn/abe_relic.git
PKG_VERSION=fba1e5ffd7fbb91c910be9023e13f0b4768d6119


.PHONY: all

all: git-download 
	"$(MAKE)" -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libabe_relic.a ${BINDIR}/abe_relic.a

clean::
	@rm -rf $(BINDIR)$(PKG_NAME).a
	"$(MAKE)" -C $(PKG_BUILDDIR) clean
	
include $(RIOTBASE)/pkg/pkg.mk