msrdir = $(MSR_LIBDIR)
msr_LTLIBRARIES = \
    mod_session_redis.la

dist_noinst_HEADERS = \
    mod_session_redis.h

SOURCES = \
    mod_session_redis.c
AM_CFLAGS = \
    $(MSR_CFLAGS)
AM_LDFLAGS = \
    $(MSR_LIBS) \
    -avoid-version \
    -module \
    -export-symbols-regex session_redis_module

install-exec-local:
	test -d /tmp/ms || mkdir -p /tmp/ms
	@APXS@ -i -n mod_session_redis -S LIBEXECDIR=$(DESTDIR)$(APXS_LIBEXECDIR) mod_session_redis.la

clean-local:
	rm -f mod_session_redis.slo mod_session_redis.la mod_session_redis.lo .libs
