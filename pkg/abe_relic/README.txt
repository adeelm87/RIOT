# Usage
Add 'USEPKG += abe_relic' in the Makefile of your project. Make sure that 
'USEPKG += relic' is included already as this library depends on relic. Also
'#include <abe_relic.h>'.

# Further information
Look to the example in 'examples/abe_relic_example' for more hints of how to 
use the library. There you can find appropriate flags for relic that will work 
with abe_relic, if you don't use these flags there might be unexpected errors
occuring.

If you need hints of how to use the library (i.e. which functions exist e.t.c.)
please look at the functions 'ma_abe_example()' and 'cp_abe_example()' of the
file 'example_usage.c'.