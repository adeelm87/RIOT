APPLICATION = ccn-lite-relay

# If no BOARD is found in the environment, use this default:
BOARD ?= native

BOARD_WHITELIST := fox iotlab-m3 msba2 mulle native pba-d-01-kw2x samr21-xpro


# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

CFLAGS += -DDEVELHELP
CFLAGS += -DUSE_LINKLAYER
CFLAGS += -DCCNL_UAPI_H_
CFLAGS += -DUSE_SUITE_NDNTLV
CFLAGS += -DNEEDS_PREFIX_MATCHING
CFLAGS += -DNEEDS_PACKET_CRAFTING

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

USEMODULE += ps
USEMODULE += shell
USEMODULE += shell_commands
# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += timex
USEMODULE += xtimer
USEMODULE += random
USEMODULE += prng_minstd

USEPKG += tlsf

export RELIC_CONFIG_FLAGS=-DALLOC=AUTO -DFP_PRIME=256 \
-DBN_PRECI=1024 -DSTRIP=ON -DSEED=LIBC -DARCH=ARM \
-DWITH="DV;BN;MD;PC;EP;FP;EPX;PP;FPX;BC" -DOPSYS=NONE -DCOLOR=OFF -DWORD=32 

USEPKG += relic
USEPKG += abe_relic

USEPKG += ccn-lite
USEMODULE += ccn-lite-utils

include $(RIOTBASE)/Makefile.include
