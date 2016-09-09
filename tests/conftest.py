import pytest
import os
import shutil
from string import Template
import random
import subprocess
import time
import socket
from redis import StrictRedis
from redis.sentinel import Sentinel

__COOKIE_NAME__ = 'ap_session'

def getsocketport():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("",0))
        s.listen(1)
        port = s.getsockname()[1]
        return port

def isportopen(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1',port)) == 0

testdir = os.path.join(os.getcwd(), 'testdir')
HOSTNAME = 'localhost'
IPADDR = '127.0.0.1'

@pytest.fixture(scope='module')
def http_port(request):
    var = str(getsocketport())
    return var

@pytest.fixture(scope='module')
def cookie_name(request):
    return __COOKIE_NAME__

@pytest.fixture(scope='module')
def ap(redp, request, http_port):
    httpdir = os.path.join(testdir, 'apache2')
    if os.path.exists(httpdir):
        shutil.rmtree(httpdir)
    os.makedirs(httpdir)
    os.mkdir(os.path.join(httpdir, 'conf.d'))
    os.mkdir(os.path.join(httpdir, 'html'))
    logsdir = os.path.join(httpdir, 'logs')
    os.mkdir(logsdir)
    os.symlink('/usr/lib/apache2/modules', os.path.join(httpdir, 'modules'))

    shutil.copy('src/.libs/mod_session_redis.so', httpdir)

    wsgidir = os.path.join(os.getcwd(),'tests')
    with open('tests/httpd.conf') as f:
        t = Template(f.read())
        senhost = senaddrs[0]
        text = t.substitute({'HTTPROOT': httpdir,
                             'HTTPNAME': HOSTNAME,
                             'HTTPADDR': IPADDR,
                             'COOKIE_NAME': __COOKIE_NAME__,
                             'HTTPPORT': http_port,
                             'HTPASSWD_FILE': os.path.join(os.getcwd(), 'tests', 'authfile'),
                             'WSGI_DIR': wsgidir,
                             'WSGI_MODULE': os.path.join(wsgidir,'wsgi.py'),
                             'SENTINEL_HOST': senhost[0],
                             'SENTINEL_PORT': str(senhost[1]),
                             'REDIS_MASTER_GROUP_NAME': redis_mgn})
    config = os.path.join(httpdir, 'httpd.conf')
    with open(config, 'w+') as f:
        f.write(text)

    httpenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin',
               'MALLOC_CHECK_': '3',
               'MALLOC_PERTURB_': str(random.randint(0, 32767) % 255 + 1)}

    p = subprocess.Popen(['apache2', '-DFOREGROUND', '-f', config],
                         env=httpenv, preexec_fn=os.setsid)

    # Wait for pid file and for apache2 to write in error log file
    while not os.path.exists(os.path.join(httpdir, 'apache2.pid')) and not \
          os.path.exists(os.path.join(logsdir, 'error_log')):
        time.sleep(0.1)

    def fin():
        print ("finalize apache2 process")
        p.terminate()
        # try:
        #     outs, errs = p.communicate(timeout=15)
        # except TimeoutExpired:
        #     p.kill()
        #     outs, errs = p.communicate()
        # print(outs)
        # print(errs)
        # p.terminate()
    request.addfinalizer(fin)
    return p



redps = []
senps = []
senaddrs = []
redaddrs = []
redis_mgn = 'redistestcluster'

@pytest.fixture(scope='module')
def redp(request):
    redis_master_ip_address = ''
    redis_master_ip_port = ''
    redisslaveof = ''
    for i in range(0, 3):
        redisdir = os.path.join(testdir, 'redis%s' % str(i))
        if os.path.exists(redisdir):
            shutil.rmtree(redisdir)
        os.makedirs(redisdir)

        redissocketfile = os.path.join(testdir, 'apache2', 'redis%s.sock' % str(i))

        with open('tests/redis%s.conf' % str(i)) as f:
            t = Template(f.read())
            redisport = getsocketport()
            redaddrs.append((IPADDR, redisport))
            text = t.substitute({'REDISDIR': redisdir,
                                 'REDIS_MASTER_GROUP_NAME': redis_mgn,
                                 'REDIS_IP_ADDRESS': IPADDR,
                                 'REDIS_IP_PORT': redisport,
                                 'REDIS_SLAVEOF': redisslaveof,
                                 'REDIS_MASTER_IP_ADDRESS': redis_master_ip_address,
                                 'REDIS_MASTER_IP_PORT': redis_master_ip_port})
            if (i == 0):
                redis_master_ip_port = redisport
        redisconfig = os.path.join(redisdir, 'redis.conf')
        with open(redisconfig, 'w+') as f:
            f.write(text)

        if not redis_master_ip_address:
            redis_master_ip_address = IPADDR
            redisslaveof = 'slaveof'

        senlogfilename = "redis-sentinel.log"
        sendir = os.path.join(testdir, 'sentinel%s' % str(i))
        if os.path.exists(sendir):
            shutil.rmtree(sendir)
        os.makedirs(sendir)
        with open('tests/sentinel%s.conf' % str(i)) as f:
            t = Template(f.read())
            senport = getsocketport()
            senaddrs.append((IPADDR, senport))
            text = t.substitute({'SENTINELDIR': sendir,
                                 'REDIS_MASTER_GROUP_NAME': redis_mgn,
                                 'SENTINEL_IP_ADDRESS': IPADDR,
                                 'SENTINEL_IP_PORT': senport,
                                 'REDIS_MASTER_IP_ADDRESS': redis_master_ip_address,
                                 'REDIS_MASTER_IP_PORT': redis_master_ip_port,
                                 'QUORUM': str(2)})
        senconfig = os.path.join(sendir, 'sentinel.conf')
        with open(senconfig, 'w+') as f:
            f.write(text)

        redisenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin'}
        redislogfilename = "redis-server.log"

        p = subprocess.Popen(['redis-server', redisconfig],
                             env=redisenv, preexec_fn=os.setsid,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        redislogfilepath = os.path.join(redisdir, redislogfilename)
        while not os.path.exists(redislogfilename) and p.returncode is not None \
              and not isportopen(redisport):
            time.sleep(0.05)

        redps.append(p)

        p = subprocess.Popen(['redis-sentinel', senconfig, '--loglevel', 'verbose'],
                             env=redisenv, preexec_fn=os.setsid,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        senlogfilepath = os.path.join(sendir, senlogfilename)
        while not os.path.exists(senlogfilepath) and p.returncode is not None \
              and not isportopen(senport):
            time.sleep(0.05)

        senps.append(p)

    # Check and wait for slaves to be in sync and sentinels has elected a master
    master_ready = False
    slaves_ready = False
    sentinels_ready = False
    count = 0
    maxcount = 10
    waittime = 0.5
    while(not master_ready or not slaves_ready or not sentinels_ready):
        for redaddr in redaddrs:
            host = redaddr[0]
            port = redaddr[1]
            r = StrictRedis(host=host, port=int(port))
            repinfo = r.info(section='replication')
            role = repinfo.get('role')
            if port == redis_master_ip_port:
                master_ready = role == 'master' and repinfo.get('connected_slaves') == 2
            else:
                slaves_ready = role == 'slave' and repinfo.get('master_sync_in_progress') == 0
        s = Sentinel(senaddrs, socket_timeout=0.1)
        sentinels_ready = len(s.discover_master(redis_mgn)) is not None and \
                          len(s.discover_slaves(redis_mgn)) == 2
        if count >= maxcount:
            raise Exception('waited too long for sentinels to be done')
        time.sleep(waittime)

    def fin():
        print ("finalize redis-sentinel processes")
        for p in senps:
            p.terminate()
        print ("finalize redis-server processes")
        for p in redps:
            p.terminate()
    request.addfinalizer(fin)
    return True
