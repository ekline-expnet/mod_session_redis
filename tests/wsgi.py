from cherrypy import expose, request, response, tree
from urllib.parse import urlencode, parse_qs
import sys
import os

class Root():

    @expose
    def index(*args, **kwargs):
        seskey = 'HTTP_SESSION'
        http_ses = request.wsgi_environ.get(seskey)
        if http_ses:
            print('%s found:"%s"' % (seskey, http_ses), file=sys.stderr, flush=True)
            keys = parse_qs(http_ses,
                            strict_parsing=True,
                            encoding='ASCII')
            print(keys, file=sys.stderr, flush=True)
            if 'foo' in keys:
                keys['foo'][0] = int(keys['foo'][0]) + 1
        else:
            print('%s not found' % (seskey), file=sys.stderr, flush=True)
            keys = {'foo': [1],
                    'bar': ['#56/&522@#']}
        sestring = urlencode(keys, doseq=True, encoding='ASCII')
        print('Setting %s' % sestring, file=sys.stderr, flush=True)
        response.headers['X-Replace-Session'] = sestring
        return "<html><body>Test</body></html>"

    @expose
    def auth(*args, **kwargs):
        return "<html><body>Authorized</body></html>"

def application(env, start_response):
    cfg = {
        '/': {
            'foo': 'bar'
        }
    }
    app = tree.mount(Root(),
                              script_name='/',
                              config=cfg)
    return tree(env, start_response)
