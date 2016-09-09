from cherrypy import expose, request, response, tree
from cherrypy import tools
from urllib.parse import urlencode, parse_qs
import sys
import os


class Root():

    @expose
    @tools.json_out()
    def auth(self, **kwargs):
        return self.index()

    @expose
    @tools.json_out()
    def index(self, **kwargs):
        staticvalue = '#56/&522@#'
        seskey = 'HTTP_SESSION'
        http_ses = request.wsgi_environ.get(seskey)
        if http_ses:
            # print('%s found:"%s"' % (seskey, http_ses), file=sys.stderr, flush=True)
            keys = parse_qs(http_ses,
                            strict_parsing=True,
                            encoding='ASCII')
            # print(keys, file=sys.stderr, flush=True)
            # print('%s not found' % (seskey), file=sys.stderr, flush=True)
        else:
            keys = dict()
            
        if 'foo' not in keys:
            keys['foo'] = [0]
        if 'bar' not in keys:
            keys['bar'] = staticvalue
            
        keys['foo'][0] = int(keys['foo'][0]) + 1
        sestring = urlencode(keys, doseq=True, encoding='ASCII')
        # print('Setting %s' % sestring, file=sys.stderr, flush=True)
        response.headers['X-Replace-Session'] = sestring
        return keys


def application(env, start_response):
    cfg = {
        '/': {
            'foo': 'bar'
        }
    }
    app = tree.mount(Root(), script_name='/', config=cfg)
    return tree(env, start_response)
