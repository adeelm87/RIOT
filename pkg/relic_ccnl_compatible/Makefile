PKG_NAME=relic_ccnl_compatible
PKG_URL=ssh://gitolite@forge.ericsson.net/abe-icn/relic_ccnl_compatible.git
PKG_VERSION=143a4d038e97f5fd99feda638ba95c1b2d1d3a69

ifneq ($(RIOTBASE),)
INCLUDES += -I$(RIOTBASE)/sys/include -I$(RIOTBASE)/sys/net/include \
			-I$(RIOTBASE)/sys/posix/include -I$(RIOTBASE)/sys/posix/pnet/include
endif

.PHONY: all

all: $(PKG_BUILDDIR)/Makefile
	"$(MAKE)" -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/lib/librelic_s.a ${BINDIR}/${PKG_NAME}.a

$(PKG_BUILDDIR)/Makefile: git-download
	cd "$(PKG_BUILDDIR)" && COMP="$(filter-out -Werror=old-style-definition -Werror=strict-prototypes, $(CFLAGS) ) " cmake -DCMAKE_TOOLCHAIN_FILE=comp-options.cmake -DCHECK=off -DTESTS=0 -DBENCH=0 -DSHLIB=off -Wno-dev $(RELIC_CONFIG_FLAGS) .


clean::
	@rm -rf $(BINDIR)$(PKG_NAME).a
	"$(MAKE)" -C $(PKG_BUILDDIR) clean
	
include $(RIOTBASE)/pkg/pkg.mk