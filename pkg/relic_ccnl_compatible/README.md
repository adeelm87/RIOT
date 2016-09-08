---------Info------------
This is the same relic version as RIOT provides but with all ERROR changed to 
RELIC_ERROR in order avoid conflicts with ccn-lite (which also has the ERROR 
define).

---------Usage-----------
In the Makefile of the application add: "USEPKG += relic_ccnl_compatible"
and in the source file include "#include <relic.h>".