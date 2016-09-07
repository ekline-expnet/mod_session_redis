/* Copyright (C) 2015, 2016 mod_session_redis contributors - See COPYING for (C) terms */

#include "mod_session_redis.h"

#define MOD_SESSION_REDIS "mod_session_redis"

module AP_MODULE_DECLARE_DATA session_redis_module;

APLOG_USE_MODULE(session_redis);


typedef struct {

	struct {
		const char *name;
		const char *name_attrs;
		int name_set;
		int per_user;
		int per_user_set;
		int remove_flag;
		int remove_flag_set;
	} cookie;

	const char *host;
	int host_set;
	const char *socket;
	int socket_set;
	int port;
	int port_set;
	int db;
	int db_set;
	int is_sentinel;
	int is_sentinel_set;
	const char *sentinel_master_gn;
	int sentinel_master_gn_set;

} redis_cfg;

const struct timeval timeout = { 30, 0 };

static redis_cfg config;

redisReply *exe_check(redisContext *ctx, const char *format, ...) {
	va_list argp;
    void *reply = NULL;
    va_start(argp,format);
	redisReply *r = redisvCommand(ctx, format, argp);
	va_end(argp);

	if (r == NULL || r->type == REDIS_REPLY_ERROR) {
		// create full query
		// TODO: better command parsing and visualization
		char *cmd;
		int len = redisvFormatCommand(&cmd,format,argp);
		if (len == -1) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "exe_check rediscFormatCommand: out of memory");
		} else if (len == -2) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "exe_check rediscFormatCommand: invalid format string");
		}
		if (cmd == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "exe_check no query command produced");
		} else if (r == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "exe_check command '%s' returned NULL", cmd);
		} else if (r->type == REDIS_REPLY_ERROR) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "exe_check command '%s' returned error '%s'", cmd, r->str);
		}
	}

	return r;
}

redisContext *get_rw_ctx() {
	redisContext *ctx = NULL;

	if (config.host_set && config.socket_set) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Both hostname and socket was set. Only one of them can be used at the time");
	} else if (config.host_set && config.port_set) {
		ctx = redisConnectWithTimeout(config.host, config.port, timeout);
	} else if (!config.host_set && config.port_set ||
			   config.host_set && !config.port_set) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "When using hostname or ports both must be set.");
	} else if (config.socket_set) {
		ctx = redisConnectUnixWithTimeout(config.socket, timeout);
	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Neither hostname or socket was set.");
	}

	if (ctx->err) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Connection error: %s", ctx->errstr);
		redisFree(ctx);
	} else {
		redisReply *r = NULL;
		if (config.is_sentinel_set && config.is_sentinel &&
			config.sentinel_master_gn_set) {
			r = exe_check(ctx, "SENTINEL master %s", config.sentinel_master_gn);
			freeReplyObject(r);
		}

		int db = 0;
		if (config.db_set) {
			db = config.db;
		}

		r = exe_check(ctx, "SELECT %d", db);
		freeReplyObject(r);
	}

	return ctx;
}

apr_status_t redis_save(request_rec * r, const char *oldkey,
						const char *newkey, const char *val, apr_int64_t expiry) {
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "saving oldkey=\'%s\', newkey=\'%s\', val=\'%s\', expiry=\'%ld\'", oldkey, newkey, val, expiry);

	redisContext *ctx = get_rw_ctx();

	if (ctx == NULL) {
		return APR_EGENERAL;
	}

	redisFree(ctx);

	return APR_SUCCESS;
}

apr_status_t redis_load(apr_pool_t *p, request_rec * r,
						const char *key, const char **val) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "loading key=\'%s\'", key);
	return APR_SUCCESS;
}

apr_status_t redis_remove(request_rec * r, const char *key) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r, "removing key=\'%s\'", key);
	return APR_SUCCESS;
}

static apr_status_t session_redis_save(request_rec *r, session_rec *z) {
	// Save session
    apr_status_t ret = APR_SUCCESS;

	/* don't cache pages with a session */
	/* FIXME: Is this the job of a session module to figure out? */
	/* apr_table_addn(r->headers_out, "Cache-Control", "no-cache"); */

	if (config.cookie.per_user) {
        if (r->user) {
            ret = redis_save(r, r->user, r->user, z->encoded, z->expiry);
            if (ret != APR_SUCCESS) {
                return ret;
            }
            return OK;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01865)
               "peruser sessions can only be saved if a user is logged in, "
                          "session not saved: %s", r->uri);
        }
	} else if (config.cookie.name_set) {
        char *oldkey = NULL, *newkey = NULL;

        /* don't cache pages with a session */
        apr_table_addn(r->headers_out, "Cache-Control", "no-cache");

        /* if the session is new or changed, make a new session ID */
        if (z->uuid) {
            oldkey = apr_pcalloc(r->pool, APR_UUID_FORMATTED_LENGTH + 1);
            apr_uuid_format(oldkey, z->uuid);
        }
        if (z->dirty || !oldkey) {
            z->uuid = apr_pcalloc(z->pool, sizeof(apr_uuid_t));
            apr_uuid_get(z->uuid);
            newkey = apr_pcalloc(r->pool, APR_UUID_FORMATTED_LENGTH + 1);
            apr_uuid_format(newkey, z->uuid);
        }
        else {
            newkey = oldkey;
        }

        /* save the session with the uuid as key */
        if (z->encoded && z->encoded[0]) {
            ret = redis_save(r, oldkey, newkey, z->encoded, z->expiry);
        }
        else {
            ret = redis_remove(r, oldkey);
        }
        if (ret != APR_SUCCESS) {
            return ret;
        }

        if (config.cookie.name_set) {
            ap_cookie_write(r, config.cookie.name, newkey, config.cookie.name_attrs, z->maxage, r->headers_out, r->err_headers_out, NULL);
        }

	} else {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "no cookie name is set or peruser cookies not enabled");
	}

	return OK;
}

static apr_status_t session_redis_load(request_rec *r, session_rec **z) {
	//Load session if cookie exists in headers. Else create new.
    apr_status_t ret = APR_SUCCESS;
    session_rec *zz = NULL;
    const char *name = NULL;
    const char *note = NULL;
    const char *val = NULL;
    const char *key = NULL;
    request_rec *m = r->main ? r->main : r;

    /* is our session in a cookie? */
	if (config.cookie.name_set) {
        name = config.cookie.name;
    } else if (config.cookie.per_user && r->user) {
        name = r->user;
    } else {
        return DECLINED;
    }

    /* first look in the notes */
	/* FIXME: Why? */
    note = apr_pstrcat(m->pool, MOD_SESSION_REDIS, name, NULL);
    zz = (session_rec *)apr_table_get(m->notes, note);
    if (zz) {
        *z = zz;
        return OK;
    }

    /* load anonymous sessions */
    if (config.cookie.name_set) {
        /* load an RFC2965 compliant cookie */
        ap_cookie_read(r, name, &key, config.cookie.remove_flag);
        if (key) {
            ret = redis_load(m->pool, r, key, &val);
            if (ret != APR_SUCCESS) {
                return ret;
            }
        }
    } else if (config.cookie.per_user) {
		/* load named session */
		if (r->user) {
            ret = redis_load(m->pool, r, r->user, &val);
            if (ret != APR_SUCCESS) {
                return ret;
            }
        }
    } else {
		/* otherwise not for us */
        return DECLINED;
    }

    /* create a new session and return it */
    zz = (session_rec *) apr_pcalloc(m->pool, sizeof(session_rec));
    zz->pool = m->pool;
    zz->entries = apr_table_make(zz->pool, 10);
    if (key && val) {
        apr_uuid_t *uuid = apr_pcalloc(zz->pool, sizeof(apr_uuid_t));
        if (APR_SUCCESS == apr_uuid_parse(uuid, key)) {
            zz->uuid = uuid;
        }
    }
    zz->encoded = val;
    *z = zz;

    /* put the session in the notes so we don't have to parse it again */
    apr_table_setn(m->notes, note, (char *)zz);

    return OK;
}

static int session_redis_monitor(apr_pool_t *p, server_rec *s) {
	/* some housekeeping up */

	return OK;
}

static int session_redis_init(apr_pool_t *p, apr_pool_t *plog,
							  apr_pool_t *ptemp, server_rec *s) {
	/* session_crypto_init() will be called twice. Don't bother
	 * going through all of the initialization on the first call
	 * because it will just be thrown away.*/
	if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
		return OK;
	}

	return OK;
}

static const char *check_string(cmd_parms * cmd, const char *string)
{
    if (APR_SUCCESS != ap_cookie_check_string(string)) {
        return apr_pstrcat(cmd->pool, cmd->directive->directive,
                           " cannot be empty, or contain '=', ';' or '&'.",
                           NULL);
    }
    return NULL;
}


static const char *set_cookie_remove(cmd_parms * parms, void *dconf, int flag)
{
    redis_cfg *conf = dconf;

    config.cookie.remove_flag = flag;
    config.cookie.remove_flag_set = true;

    return NULL;
}

static const char *set_redis_is_sentinel(cmd_parms * parms, void *dconf, int flag)
{
    redis_cfg *conf = dconf;

    config.is_sentinel = flag;
    config.is_sentinel_set = true;

    return NULL;
}

static const char *set_cookie_name(cmd_parms *cmd, void *cfg, const char *args) {
    char *last;
    char *line = apr_pstrdup(cmd->pool, args);
    char *cookie = apr_strtok(line, " \t", &last);
    config.cookie.name = cookie;
    config.cookie.name_set = 1;
    while (apr_isspace(*last)) {
        last++;
    }
    config.cookie.name_attrs = last;
    return check_string(cmd, cookie);
}

static const char *set_redis_hostname(cmd_parms *cmd, void *cfg, const char *args) {
	config.host = args;
	config.host_set = 1;
	return NULL;
}

static const char *set_redis_sentinel_master_group_name(cmd_parms *cmd, void *cfg, const char *args) {
	config.sentinel_master_gn = args;
	config.sentinel_master_gn_set = 1;
	return NULL;
}

static const char *set_redis_port(cmd_parms *cmd, void *cfg, const char *args) {
	char *line = apr_pstrdup(cmd->pool, args);
	config.port = atoi(line);
	config.port_set = 1;
	return NULL;
}

static const char *set_redis_socket(cmd_parms *cmd, void *cfg, const char *args) {
	config.socket = args;
	config.socket_set = 1;
	return NULL;
}

static const char *set_redis_database(cmd_parms *cmd, void *cfg, const char *args) {
	config.db = atoi(args);
	config.db_set = 1;
	return NULL;
}

static void register_hooks(apr_pool_t *p) {
	ap_hook_session_load(session_redis_load, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_session_save(session_redis_save, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_monitor(session_redis_monitor, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec session_redis_cmds[] =
	{
		AP_INIT_FLAG("SessionRedisCookieRemove", set_cookie_remove, NULL, ACCESS_CONF,
					 "Remove the session cookie after session load. On by default."),
		AP_INIT_FLAG("SessionRedisHostIsSentinel", set_redis_is_sentinel, NULL, ACCESS_CONF,
					 "The specified host is a Redis Sentinel. Off by default."),
		AP_INIT_RAW_ARGS("SessionRedisCookieName", set_cookie_name, NULL, ACCESS_CONF,
						 "The name of the RFC2965 cookie carrying the session key"),
		AP_INIT_TAKE1("SessionRedisHostname", set_redis_hostname, NULL, ACCESS_CONF,
					  "Hostname of the Redis host. Remember to set the port, and leave the socket option"),
		AP_INIT_TAKE1("SessionRedisSentinelMasterGroupName", set_redis_sentinel_master_group_name, NULL, ACCESS_CONF,
					  "Name of the Sentinel master group name to ask for"),
		AP_INIT_TAKE1("SessionRedisPort", set_redis_port, NULL, ACCESS_CONF,

					  "Port of the Redis host. Remember to set the hostname, and leave the socket option"),
		AP_INIT_TAKE1("SessionRedisSocket", set_redis_socket, NULL, ACCESS_CONF,
					  "Socket of the Redis host. Leave hostname and port options when using sockets"),
		AP_INIT_TAKE1("SessionRedisDatabase", set_redis_database, NULL, ACCESS_CONF,
					  "Database number to use. Defaults to 0."),
		{NULL}
	};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA session_redis_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                  /* create per-dir    config structures */
	NULL,                  /* merge  per-dir    config structures */
	NULL,                  /* create per-server config structures */
	NULL,                  /* merge  per-server config structures */
	session_redis_cmds,    /* table of config file commands       */
	register_hooks  /* register hooks                      */
};
