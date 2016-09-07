#include "sds.h"


//TODO: Move to configurable
/* const int m_defaultRetryCount = 3; */
/* const int m_defaultRetryDelay = 200; */
/* const float m_clockDriftFactor = 0.01; */
/* const char *srvs[] = { */
/* 	"/home/mkj/dev/session_redis/testdir/apache2/redis.sock" */
/* }; */

/* int g_srvmax = (int)( sizeof(srvs) / sizeof(srvs[0])); */
/* int g_retryCount; */
/* int g_retryDelay; */
/* int g_quoRum; */
/* sds g_continueLockScript; */
/* sds g_unlockScript; */


/* Use one per resource. Release after use. */
struct reslock {
	sds m_resource;
	sds m_val;
	int m_validityTime;
};

/* Turn the plain C strings into Sds strings */
char **convertToSds(int count, char** args) {
	int j;
	char **sds = (char**)malloc(sizeof(char*)*count);
	for(j = 0; j < count; j++)
		sds[j] = sdsnew(args[j]);
	return sds;
}

sds create_random_lock_id() {
	unsigned char *buffer = NULL;
	int length = 40;
	buffer = malloc((size_t)length);
	if(!buffer) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "could not allocate buffer");
	}

	if(!RAND_bytes(buffer, length)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "could not create random bytes");
	}

	/* *(buffer + length) = '\0'; */
	sds s;
	s = sdsempty();
	for (int i = 0; i < length; i++) {
		s = sdscatprintf(s, "%02X", buffer[i]);
	}
	free(buffer);
	return s;
}

bool lock_instance(redisContext *c, const char *resource,
				   const char *val, const int ttl) {
	redisReply *reply;
	reply = (redisReply *)redisCommand(c, "set %s %s px %d nx",
									   resource, val, ttl);
	if (reply && reply->str && strcmp(reply->str, "OK") == 0) {
		freeReplyObject(reply);
		return true;
	}
	if (reply) {
		freeReplyObject(reply);
	}
	return false;
}

redisReply* redis_command_argv(redisContext *c, int argc, char **inargv) {
	char **argv;
	argv = convertToSds(argc, inargv);
	/* Setup argument length */
	size_t *argvlen;
	argvlen = (size_t *)malloc(argc * sizeof(size_t));
	for (int j = 0; j < argc; j++)
		argvlen[j] = sdslen(argv[j]);
	redisReply *reply = NULL;
	reply = (redisReply *)redisCommandArgv(c, argc, (const char **)argv, argvlen);
	if (reply) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "cmd return: %lld\n", reply->integer);
	}
	free(argvlen);
	sdsfreesplitres(argv, argc);
	return reply;
}

void unlock_instance(redisContext *c,
					 const char *resource,
					 const char *val) {
	int argc = 5;
	char *unlockScriptArgv[] = {(char*)"EVAL",
								g_unlockScript,
								(char*)"1",
								(char*)resource,
								(char*)val};
	redisReply *reply = redis_command_argv(c, argc, unlockScriptArgv);
	if (reply) {
		freeReplyObject(reply);
	}
}


bool unlock(struct reslock *rl, redisContext *ctx[]) {
	/* int slen = (int)m_redisServer.size(); */
	for (int i = 0; i < g_srvmax; i++) {
		unlock_instance(ctx[i], rl->m_resource, rl->m_val);
	}
	return true;
}


bool lock(const char *resource, const int ttl, struct reslock *rl, redisContext *ctx[]) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "creating new lock id");
	sds val = create_random_lock_id(rl);
	if (!val) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "no random id created");
		return false;
	}
	rl->m_resource = sdsnew(resource);
	rl->m_val = val;
	int retryCount = g_retryCount;
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "lock id: %s. will try %d times", val, retryCount);
	int tryCount = 0;
	do {
		tryCount++;
		int n = 0;
		int startTime = (int)time(NULL) * 1000;
		for (int i = 0; i < g_srvmax; i++) {
			if (lock_instance(ctx[i], resource, val, ttl)) {
				n++;
			}
		}
		//Add 2 milliseconds to the drift to account for Redis expires
		//precision, which is 1 millisecond, plus 1 millisecond min drift
		//for small TTLs.
		int drift = (ttl * m_clockDriftFactor) + 2;
		int validityTime = ttl - ((int)time(NULL) * 1000 - startTime) - drift;
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "The resource validty time is %d, n is %d, quo is %d", validityTime, n, g_quoRum);
		if (n >= g_quoRum && validityTime > 0) {
			rl->m_validityTime = validityTime;
			return true;
		} else {
			unlock(rl, ctx);
		}
		// Wait a random delay before to retry
		int delay = rand() % g_retryDelay + floor(g_retryDelay / 2);
		usleep(delay * 1000);
		retryCount--;
	} while (retryCount > 0);
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "no lock acquired. tried %d", tryCount);
	return false;
}

void free_lock(struct reslock *rl) {
	sdsfree(rl->m_resource);
	sdsfree(rl->m_val);
}




	/* ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "init redis"); */
	/* g_continueLockScript = sdsnew("if redis.call('get', KEYS[1]) == ARGV[1] then redis.call('del', KEYS[1]) end return redis.call('set', KEYS[1], ARGV[2], 'px', ARGV[3], 'nx')"); */
	/* g_unlockScript = sdsnew("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"); */
	/* g_retryCount = m_defaultRetryCount; */
	/* g_retryDelay = m_defaultRetryDelay; */
	/* g_quoRum = g_srvmax / 2 + 1; */
