// Used for ap_hook_monitor
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <stdarg.h>

#include <ap_config.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_lib.h>
#include <httpd.h>
#include <http_log.h>
#include <http_core.h>
#include <mod_session.h>
#include <mpm_common.h>
#include <util_cookies.h>

#include <openssl/rand.h>
#include <hiredis/hiredis.h>

/* apache's httpd.h drags in empty PACKAGE_* variables.
 * undefine them to avoid annoying compile warnings as they
 * are re-defined in config.h */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"
