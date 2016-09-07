import requests
from requests.auth import HTTPBasicAuth
import threading

# count = 1
# res = [None] * count
# tp = [None] * count
# ses = [None] * count

# def http_req(url, session, idx, res):
#     res[idx] = session.get(url, auth=bauth)
    # def run_http_client():

    # for i in range(0, count):
    #     s = requests.Session()
    #     ses[i] = s
    #     t = threading.Thread(target=http_req, args=(url, s, i, res))
    #     tp[i] = t
    # for t in tp:
    #     t.start()

    # Wait for requests to finish
    # for t in tp:
    #     t.join()

    # for r in res:

def test_cookie(ap, redp, http_port, cookie_name):
    url = 'http://localhost:%s/' % http_port
    s = requests.Session()
    r = s.get(url)
    assert r.ok
    assert len(s.cookies) > 0
    v0 = s.cookies[cookie_name]
    r = s.get(url)
    assert r.ok
    assert len(s.cookies) > 0
    v1 = s.cookies[cookie_name]
    assert v0 == v1
        
def test_cookie_auth(ap, redp, http_port, cookie_name):
    bauth = HTTPBasicAuth('auser', '1234')
    url = 'http://localhost:%s/auth' % http_port
    s = requests.Session()
    r = s.get(url, auth=bauth)
    assert r.ok
    assert len(s.cookies) > 0
    v0 = s.cookies[cookie_name]
    r = s.get(url, auth=bauth)
    assert r.ok
    assert len(s.cookies) > 0
    v1 = s.cookies[cookie_name]
    assert v0 == v1
