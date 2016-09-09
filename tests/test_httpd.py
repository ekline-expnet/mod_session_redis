import requests
from requests.auth import HTTPBasicAuth
import threading
import json

jsondec = json.decoder.JSONDecoder().decode

def check_cookie(url, cookie_name, bauth=None):
    s = requests.Session()

    r = s.get(url, auth=bauth)
    assert r.ok
    assert len(s.cookies) > 0
    seskeys = jsondec(r.text)
    assert 'foo' in seskeys
    assert seskeys["foo"][0] == 1
    v0 = s.cookies[cookie_name]

    r = s.get(url, auth=bauth)
    assert r.ok
    assert len(s.cookies) > 0
    v1 = s.cookies[cookie_name]
    assert v0 == v1
    seskeys = jsondec(r.text)
    assert 'foo' in seskeys
    assert seskeys["foo"][0] == 2



def test_cookie(ap, redp, http_port, cookie_name):
    url = 'http://localhost:%s/' % http_port
    check_cookie(url, cookie_name)
        
def test_cookie_auth(ap, redp, http_port, cookie_name):
    bauth = HTTPBasicAuth('auser', '1234')
    url = 'http://localhost:%s/auth' % http_port
    check_cookie(url, cookie_name, bauth)
