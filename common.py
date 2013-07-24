import httplib
import re
import sys
from time import sleep
from urllib import urlencode

__author__ = 'Beched'

class PyWebHack:
    allowed_params = ['host', 'ssl', 'ajax', 'cut', 'sleep', 'verbose']
    verbose = False
    log = ''
    cnt_reqs = 0
    known_urls = {}
    known_subs = []
    args = {}
    current_path = ''
    add_headers = {
        'Cookie': '',
        #'Accept' : 'text/html'
        'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    }

    def __init__(self, *args, **kwargs):
        """
        The class constructor.
        :param host: a host to work with in format hostname[:port]. The only necessary parameter
        :param ssl: if True, HTTPS will be used, default value is 0
        :param ajax: if True, "X-Requested-With: XMLHttpRequest" header will be added to all HTTP requests
        :param cut: if set, all strings matching specified regexp will be removed from all HTTP responses
        :param sleep: if set, sleep after each HTTP request for the specified number of seconds, default value is 0
        :param verbose: if True, an output will be sent to STDOUT, default value is 1
        :return:
        """
        for k, v in kwargs.items():
            if k in self.allowed_params:
                self.args[k] = v
        if 'host' not in self.args:
            self.help()
            return
        if 'ajax' in self.args:
            self.add_headers['X-Requested-With'] = 'XMLHttpRequest'
        self.sleep = float(self.args.get('sleep', 0))
        self.cut = self.args.get('cut', '')
        self.scheme = 'https' if 'ssl' in self.args else 'http'
        self.host = self.args['host']
        self.handler = httplib.HTTPSConnection(self.host) if self.scheme == 'https' else httplib.HTTPConnection(
            self.host)
        self.url = '%s://%s/' % (self.scheme, self.host)
        self.verbose = self.args.get('verbose', 1)

    def __del__(self):
        """
        The class destructor. Outputs the total number of HTTP requests made
        """
        self.rep_log('==========\n%s requests made' % self.cnt_reqs)

    def rep_log(self, string, delim='\n'):
        """
        Logging method. If self.verbose is True, sents output to STDOUT
        :param string: a log entry
        :param delim: a delimiter which is appended to the entry
        """
        try:
            self.known_urls[self.current_path]['info'] += string + delim
        except:
            pass
        if self.verbose != 0:
            sys.stdout.write('%s%s' % (string, delim))

    def newstructure(self):
        """
        Generates a dictionary for holding the information about some path
        :return: a dict with all necessary (empty) fields
        """
        return {
            'args': {'get': [], 'post': [], 'cookie': []},
            #'bugs': [],
            'info': '',
            'html': None,
            'code': None,
            'hdrs': {}
        }

    def restructure(self, path):
        """
        Sets current path and generates a new structure for it, if path is new
        :param path: current path
        """
        self.current_path = path
        if path not in self.known_urls:
            self.known_urls[path] = self.newstructure()

    def help(self):
        """
        A help method template. Called when invalid input is provided to the constructor
        """
        self.rep_log(
            '==========\nLibPyWebHack\n==========\nThis is a class constructor and it accepts parameters' +
            '%s. See docs for explanation.' % (
                self.allowed_params, sys.argv[0]))

    def makereq(self, path, query=None, headers=None, method='GET'):
        """
        The core method for sending HTTP requests
        :param path: a request URI (if it's directory, it should end with '/')
        :param query: a query string
        :param headers: a dict with additional request headers
        :param method: HTTP request method
        :return: a response tuple (str body, int code, dict headers)
        """
        sleep(self.sleep)
        headers = self.add_headers if headers is None else headers
        self.cnt_reqs += 1
        if isinstance(query, dict):
            query = urlencode(query)
        try:
            if query is not None:
                self.handler.request(method, path, query, headers)
            else:
                self.handler.request(method, path, headers=headers)
            resp = self.handler.getresponse()
            return (re.sub(self.cut, '', resp.read()), resp.status, {x: y for (x, y) in resp.getheaders()})
        except httplib.HTTPException:
            self.handler = httplib.HTTPSConnection(self.host) if self.scheme == 'https' else httplib.HTTPConnection(
                self.host)
            return ('', None, None)
        except:
            self.rep_log('Could not connect to %s! Reason: %s' % (path, sys.exc_info()[1]))
            return ('', 0, {})

    def chkpath(self, paths, comment=None):
        """
        Check that the given paths exist. If some path exists, it's added to self.known_urls
        :param paths: a list with request URIs
        :param comment: a description of what's going on. Will be logged
        """
        for path in paths:
            self.rep_log('Checking for %s...' % ( '/' + path if comment is None else comment))
            r = self.makereq(self.url + path)
            if r[1] != 404:
                self.rep_log('Possibly (code %s) found at %s%s' % (r[1], self.url, path))
                self.known_urls.update({'/' + path: self.newstructure()})
