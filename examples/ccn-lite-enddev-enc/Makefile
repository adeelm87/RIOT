APPLICATION = ccn-lite-enddev-enc

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
CFLAGS += -DSENSOR_DEV

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

export RELIC_CONFIG_FLAGS=-DALLOC=AUTO -DFP_PRIME=256 \
-DBN_PRECI=1024 -DSTRIP=ON -DSEED=LIBC -DARCH=ARM \
-DWITH="DV;BN;MD;PC;EP;FP;EPX;PP;FPX;BC" -DOPSYS=NONE -DCOLOR=OFF -DWORD=32 

# Make sure to put relic first
USEPKG += relic_ccnl_compatible
USEPKG += abe_relic

USEMODULE += ps
USEMODULE += shell
USEMODULE += shell_commands
# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif

GNRC_NETIF_NUMOF := 1
USEMODULE += gnrc_netdev2
USEMODULE += at86rf233

USEMODULE += timex
USEMODULE += xtimer
USEMODULE += random
USEMODULE += prng_minstd

USEPKG += tlsf

USEPKG += ccn-lite
USEMODULE += ccn-lite-utils

include $(RIOTBASE)/Makefile.include
