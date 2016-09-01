# name of your application
APPLICATION = abe_relic_example

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

export RELIC_CONFIG_FLAGS=-DALLOC=AUTO -DFP_PRIME=256 \
-DBN_PRECI=1024 -DSTRIP=ON -DSEED=LIBC -DARCH=ARM \
-DWITH="DV;BN;MD;PC;EP;FP;EPX;PP;FPX;BC" -DOPSYS=NONE -DCOLOR=OFF -DWORD=32 

# Make sure to put relic first
USEPKG += relic
USEPKG += abe_relic

USEMODULE += ps
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += xtimer
# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
