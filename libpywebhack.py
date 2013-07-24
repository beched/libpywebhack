#!/usr/bin/env python
#-*- coding:utf-8 -*-

import socket
import threading
from common import *

__author__ = 'Beched'

class WebHack(PyWebHack):
    def softdetect(self, path):
        """
        Extract information from HTTP headers, detects various platforms and searches for some files
        :param path: target path
        """
        self.restructure(path)
        self.known_urls[path]['html'], self.known_urls[path]['code'], self.known_urls[path]['hdrs'] = self.makereq(path)

        info = '==========\nRetrieving information from %s\nResponse code: %s\nDetected server: %s\nPowered by: %s\n' \
               'Headers influencing Caching: %s\nPowered by CMS: %s\nContent Location: %s\n=========='
        info = info % (
            path, self.known_urls[path]['code'], self.known_urls[path]['hdrs'].get('server', None),
            self.known_urls[path]['hdrs'].get('x-powered-by', None), self.known_urls[path]['hdrs'].get('vary', None),
            self.known_urls[path]['hdrs'].get('x-powered-cms', None),
            self.known_urls[path]['hdrs'].get('content-location', None))
        self.rep_log(info)
        self.chkpath(
            ['sitemap.xml', 'robots.txt', 'crossdomain.xml', 'clientaccesspolicy.xml', 'phpmyadmin', 'pma', 'myadmin',
             '.svn', '.ssh', '.git', 'CVS', 'info.php', 'phpinfo.php', 'test.php'])

        try:
            for link in re.findall('%s(/[^"\'>]*)["\'>]' % self.host, self.known_urls[path]['html']):
                if link not in self.known_urls:
                    self.known_urls.update({link: self.newstructure()})
            for link in re.findall('(href|src)\s*?=\s*?["\']?([^"\'>]*)["\'>]', self.known_urls[path]['html']):
                if not link[1].startswith('http') and not link[1].startswith('//') and link not in self.known_urls:
                    self.known_urls.update({link[1] if link[1].startswith('/') else '/' + link[1]: self.newstructure()})
        except:
            pass

        try:
            if 'Apache' in self.known_urls[path]['hdrs'].get('server', None):
                self.rep_log('Apache server detected')
            elif 'nginx' in self.known_urls[path]['hdrs'].get('server', None):
                self.rep_log('NginX server detected')
            elif 'IIS' in self.known_urls[path]['hdrs'].get('server', None):
                self.rep_log('Microsoft IIS server detected')
        except TypeError:
            pass

        if re.search('(\.php[^\w]?)', path.lower()) != None or 'PHP' in self.known_urls[path]['hdrs'].get(
                'x-powered-by', '') or 'PHP' in self.known_urls[path]['hdrs'].get('set-cookie', ''):
            self.rep_log('PHP detected')
        elif re.search('(\.aspx?[^\w]?)', path.lower()) != None or 'ASP.NET' in self.known_urls[path]['hdrs'].get(
                'x-powered-by', '') or (
                self.known_urls[path]['html'] != None and '__VIEWSTATE' in self.known_urls[path]['html']):
            self.rep_log('ASP.NET detected')
        elif re.search('(\.jsp[^\w]?)', path.lower()) != None or 'JSESSIONID' in self.known_urls[path]['hdrs'].get(
                'set-cookie', '') or re.search('(Servlet)|(JSP)',
                                               self.known_urls[path]['hdrs'].get('x-powered-by', '')) != None:
            self.rep_log('Java detected')
        elif self.known_urls[path]['html'] != None and 'csrfmiddlewaretoken' in self.known_urls[path]['html']:
            self.rep_log('Python (Django) detected')
        elif 'mod_rails' in self.known_urls[path]['hdrs'].get('x-powered-by', '') or self.known_urls[path]['hdrs'].get(
                'x-runtime', None) != None or self.known_urls[path]['hdrs'].get(
                    'x-rack-cache', None) != None or self.makereq(path + '?a=a&a[]=a')[1] == 500:
            self.rep_log('Ruby on Rails or Rack server detected')

    def apachetest(self, path):
        """
        Perform some security-specific information retrieval from Apache
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting specific Apache issues')
        if not self.known_urls[path]['hdrs']:
            self.known_urls[path]['html'], self.known_urls[path]['code'], self.known_urls[path]['hdrs'] = self.makereq(
                path)
        try:
            if self.known_urls[path]['hdrs'].get('Vary', None) and re.search('(negotiate)',
                                                                             self.known_urls[path]['hdrs'].get(
                                                                                     'Vary',
                                                                                     None).lower()):
                self.rep_log('mod_negotiation possibly detected. Trying to get filename suggestions...')
                tmp_headers = self.add_headers.copy()
                tmp_headers['Negotiate'] = 'trans'
                tmp_headers['Accept'] = 'justfortest/justfortest'
                tmp_headers['Accept-Encoding'] = 'justfortest'
                tmp_headers['Accept-Language'] = 'justfortest'
                self.rep_log('Revealed names: %s' % self.makereq(path, headers=tmp_headers)[2]['Alternates'])
        except ValueError:
            pass
        self.rep_log('Trying to get real application name via invalid request...')
        tmp_headers = self.add_headers.copy()
        tmp_headers['Content-Length'] = 'x'
        html, code, _ = self.makereq(path, '', tmp_headers, 'POST')
        try:
            if code == 413:
                self.rep_log('Found real path: %s' % re.search('resource<br />(.*)<br />', html).group(1))
            else:
                self.rep_log('Failed')
        except:
            self.rep_log('Failed')
        self.chkpath(['server-status'], 'server status application')

    def nginxtest(self, path):
        """
        Hack NginX
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting specific NginX issues')

    def iistest(self, path):
        """
        Search for sensitive IIS files, perform IIS files scanning, test access restriction bypass, test ASP.NET issues
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting for specific Microsoft-IIS issues')
        self.chkpath(['WEB-INF', 'META-INF', '_vti_bin'])
        self.rep_log('Testing for IIS+PHP/ASP auth bypass through NTFS')
        if self.makereq(path + '::$INDEX_ALLOCATION')[1] != 404:
            self.rep_log('Possibly vulnerable or blocked. Check at %s' % path + '::$INDEX_ALLOCATION')
        if self.makereq(path + ':$i30:$INDEX_ALLOCATION')[1] != 404:
            self.rep_log('Possibly vulnerable or blocked. Check at %s' % path + ':$i30:$INDEX_ALLOCATION')
        self.iiscan(path)
        self.asptest(path)

    def iiscan(self, path):
        """
        Tilde (~) and wildcard (*) file names brute force in IIS
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTrying to retrieve content of the current IIS directory')
        alph = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
        if self.makereq(path + '*~1*/.aspx')[1] == 404:
            tail = '/.aspx'
            self.rep_log('IIS 6 possibly detected')
        elif self.makereq(path + '*~1*')[1] == 404:
            tail = ''
            self.rep_log('IIS 5.x possibly detected')
        elif self.makereq(path + '*~1*/')[1] == 404:
            tail = '/'
            self.rep_log('IIS 7.x, .NET 2 possibly detected (no error handling)')
        else:
            self.rep_log('No files in current directory, or technique does not work')
            return
        names, i = [''], 0
        while True:
            is_valid = True
            if i >= len(names):
                break
            while is_valid:
                payload, name, is_valid, is_first = '%s%s%s*~1*%s', names[i], False, True
                for c in alph:
                    if self.makereq(payload % (path, name, c, tail))[1] == 404:
                        is_valid = True
                        if is_first:
                            is_first = False
                            names[i] += c
                            self.rep_log('(Part of some file or directory name: %s%s)' % (path, names[i]))
                        else:
                            names.append(name + c)
                if not is_valid:
                    names[i] += '~1'
                    if self.makereq('%s%s*%s' % (path, names[i], tail))[1] != 404:
                        self.rep_log('(Some short name prefix: %s. Now determining an extension)' % name)
                        payload = '%s%s%s*%s'
                        is_valid = True
            i += 1
        self.rep_log('==========\nFound short names in %s:\n%s' % (path, '\n'.join(names)))

    def phptest(self, path):
        """
        Check for RCE, try to get PHP script path disclosure
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting specific PHP issues\nTesting for CVE-2012-1823...')
        html, code, hdrs = self.makereq(path + '?-s+%3d')
        if ( html.startswith('<code><span') and html != self.known_urls[path]['html']):
            self.rep_log('Possibly vulnerable to RCE. Check at %s?-s+%%3d' % path)
        else:
            self.rep_log('Not vulnerable')
        self.rep_log(
            'Testing for common PHP-(Fast)CGI+NginX|IIS|Apache|LightHTTPD|(.*?) configuration vulnerability...')
        if len(self.known_urls) == 0:
            html, code, hdrs = self.makereq('/index.html')
            if ( code != 404):
                self.known_urls.append('index.html')
            else:
                html, code, hdrs = self.makereq('/favicon.ico')
            if ( code != 404): self.known_urls.append('favicon.ico')
        if len(self.known_urls) != 0:
            test = self.makereq(path)
            test1 = self.makereq(path + '/.php')
            if test[1] != 404 and len(test[0]) == len(test1[0]):
                self.rep_log('Possibly vulnerable. Check it out at %s/.php' % path)
                return
            test2 = self.makereq(path + '%00.php')
            if test[1] != 404 and len(test[0]) == len(test2[0]):
                self.rep_log('Possibly vulnerable. Check it out at %s%%00.php' % path)
            else:
                self.rep_log('Not vulnerable')
        else:
            self.rep_log('No files found to check')
        self.rep_log('Trying to get an error sending invalid session id...')
        tmp_headers = self.add_headers.copy()
        tmp_headers['Cookie'] += ';PHPSESSID=(.)(.)'
        html, _, _ = self.makereq(path, headers=tmp_headers)
        spath = re.search('in <b>(.*)</b> on line', html)
        if spath != None:
            self.rep_log('Found server application path: %s' % spath.group(1))
        else:
            self.rep_log(
                'Failed\nTrying to get a max_execution_time error by sending a file with long name...\n' +
                'It can take time, wait...')
            tmp_headers = self.add_headers.copy()
            tmp_headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------31133713371337'
            file = '---------------------------31133713371337\r\n' \
                'Content-Disposition: form-data; name=file31337; filename=\r\njustfortest%s.txt\r\n' \
                'Content-Type: text/plain\r\n\r\njustfortest\r\n---------------------------31133713371337\r\n'
            file = file % '0' * 100500
            tmp_headers['Content-Length'] = len(file)
            html, code, hdrs = self.makereq(path, file, tmp_headers, 'POST')
            spath = re.search('in <b>(.*)</b> on line', html)
            if spath != None:
                self.rep_log('Found server application path: %s' % spath.group(1))
            else:
                self.rep_log('Failed')
                if self.known_urls[path]['args'] == []:
                    self.rep_log('I need to know script parameters in order to provoke the next PHP errors.')
                    return
                self.rep_log(
                    'Trying to get a type error or a max_execution_time error by exceeding memory_limit...\n' +
                    'Considering max_input_nesting_level = 64...\nIt can take time, wait...')
                query = '=1&'.join([x + '[]' * 64 for x in
                                    self.known_urls[path]['args']['get'] + self.known_urls[path]['args']['post'] +
                                    self.known_urls[path]['args']['cookie']]) + '=1&'
                tmp_headers = self.add_headers.copy()
                tmp_headers['Cookie'] = query.replace('&', ';')
                tmp_headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
                html, code, hdrs = self.makereq('%s?%s' % (path, query), query, tmp_headers, 'POST')
                path = re.search('in <b>(.*)</b> on line', html)
                if ( path != None):
                    self.rep_log('Found server application path: %s' % path.group(1))
                else:
                    self.rep_log('Failed')

    def asptest(self, path):
        """
        Search for some sensitive .NET-specific files
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting specific ASP.NET issues')
        try:
            self.rep_log('ASP.NET version: %s' % self.known_urls[path]['hdrs']['x-aspnet-version'])
        except:
            pass
        self.chkpath(['Trace.axd', 'elmah.axd', 'ScriptResource.axd?d=A', 'WebResource.axd?d=A'])

    def javatest(self, path):
        """
        Hack Java
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting specific Java issues')

    def rubytest(self, path):
        """
        Retrieve information from HTTP headers, check for RoR object deserialization RCE
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting Ruby on Rails framework and/or Rack web-server issues')
        try:
            self.rep_log(
                'RoR project name: %s' % re.search('_(.*)_sess',
                                                   self.known_urls[path]['hdrs'].get('set-cookie', '').group(1))
            )
        except:
            pass
        self.rep_log('==========\nTesting for CVE-2013-0156...')
        tmp_headers = self.add_headers.copy()
        tmp_headers['Content-Type'] = 'application/xml'
        pload = '<?xml version="1.0" encoding="UTF-8"?>\n<probe type="%s"><![CDATA[\n%s\n]]></probe>'
        _, code1, _ = self.makereq(path, pload % ('string', 'hello'), tmp_headers, 'POST')
        _, code2, _ = self.makereq(path, pload % ('yaml', '--- !ruby/object:Time {}\n'), tmp_headers, 'POST')
        _, code3, _ = self.makereq(path, pload % ('yaml', '--- !ruby/object:\x00'), tmp_headers, 'POST')
        if code2 == code1 and code3 != code2 and code3 != 200:
            self.rep_log('Possibly vulnerable to RCE')

    def pytest(self, path):
        """
        Hack Django
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nTesting specific Python with Django framework issues')

    def gpcreq(self, path, query='', mode='get'):
        #mode = 'head' if self.cut == '' else 'get' if mode == None else mode
        """
        self.restructure(path)
        Send data via GET, POST request or in Cookie-header
        :param path: target path
        :param query: URL-encoded QUERY_STRING
        :param mode: 'get', 'post' or 'cookie'
        :return:
        """
        method = mode.upper()
        if mode == 'post':
            tmp_headers = self.add_headers.copy()
            tmp_headers['Content-Type'] = 'application/x-www-form-urlencoded'
            resp = self.makereq(path, query, tmp_headers, 'POST')
        elif mode == 'cookie':
            tmp_headers = self.add_headers.copy()
            tmp_headers['Cookie'] = query.replace('&', ';')
            resp = self.makereq(path, headers=tmp_headers)
        else:
            resp = self.makereq(path + ('?' if '?' not in path else '&') + query, method=method)
        return resp

    def argsfind(self, path, modes=['get'], fill='1', base='bases/argsbase.txt', fix=[]):
        """
        Search for the input parameters of the web-scenario
        :param path: target path
        :param modes: list of the data transition methods ('get', 'post' or 'cookie')
        :param fill: the payload which should be plugged into parameters
        :param base: path to file with parameter names
        :param fix: fixed points, i.e. a list of parameters which should be sent in each request
        """
        self.restructure(path)
        base = [x.strip() for x in open(base)]

        def args_dichotomy(base):
            self.rep_log('.', delim='')
            params = dict([(x, fill ) for x in base])
            query = urlencode(params)
            l = len(base)
            html, code, hdrs = self.gpcreq(path, query, mode)
            if html is None:
                pass
            if code == 414 or (code == 400 and mode == 'cookie'):
                self.rep_log('Too big base, splitting...')
                args_dichotomy(fix + base[:int(l / 2)])
                args_dichotomy(fix + base[int(l / 2):l])
                return
            if hdrs.get('Content-Length', len(html)) != len(self.known_urls[path]['html']) \
                or code != self.known_urls[path]['code']:
                self.rep_log('*', delim='')
                if l == 1:
                    self.known_urls[path]['args'][mode] += params
                else:
                    args_dichotomy(fix + base[:int(l / 2)])
                    args_dichotomy(fix + base[int(l / 2):l])

        self.rep_log(
            '==========\nSearching for the %s-parameters of %s\n%s' % (modes, path, len(base)) +
            ' items loaded from the base\nDetecting the default page length and HTTP-code...'
        )
        if self.known_urls[path]['html'] is None:
            self.known_urls[path]['html'], self.known_urls[path]['code'], self.known_urls[path]['hdrs'] = self.gpcreq(
                path=path)
        for mode in modes:
            self.rep_log('==========\nStarting dichotomy for %s-params...\n==========' % mode.upper())
            #max_input_vars in PHP is 1001
            for x in [base[1001 * i: 1001 * (i + 1)] for i in xrange((len(base) + 1000 ) / 1001)]:
                args_dichotomy(fix + x)
            self.rep_log('\n==========\nFound parameters: %s' % ','.join(set(self.known_urls[path]['args'][mode])))

    def fuzzbackups(self, path):
        """
        Search for source code backups of the script
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nSearching for the back-ups of %s' % path)
        pieces = path.split('/')
        path = '/'.join(pieces[:-1])[1:] + '/'
        filename = pieces[-1]
        parts = filename.split('.')
        self.chkpath(
            ['%s%s.bak' % (path, '.'.join(parts[:-1]) if len(parts) > 2 else parts[0]), '%s%s.bak' % (path, filename),
             '%s%s.old' % (path, filename)], 'generic backups')
        self.chkpath(['%s%s.swp' % (path, filename), '%s%s.swo' % (path, filename), '%s.%s.swp' % (path, filename)],
                     'Vim swap files')
        self.chkpath(['%s%s~' % (path, filename)], 'Vim, Gedit temporary file')
        self.chkpath(['%sCopy%%20of%%20%s' % (path, filename), '%s%s%%20copy%s' % (
            path, '.'.join(parts[:-1]) if len(parts) > 2 else parts[0], '.' + parts[-1] if len(parts) > 1 else '')],
                     'Windows or MacOS copies of the file')
        self.chkpath(['%s%%23%s%%23' % (path, filename)], 'Emacs temporary file')
        self.chkpath(['%s%s.save' % (path, filename), '%s%s.save.1' % (path, filename)], 'GNU Nano temporary files')
        self.chkpath(['%s.%%23%s' % (path, filename)], 'MCEdit temporary files')
        self.chkpath(['%s.%s.un~' % (path, filename)], 'Deleted files')
        self.chkpath(['%s%ss' % (path, filename)], '(PHP) source code')

    def brutesubs(self, threads=5, words='bases/wordlist2.txt', ban_codes=None, ban_regex=None):
        """
        Multi-threaded brute force of existing subdomains of the given domain
        :param threads: number of threads
        :param words: path to file with subdomain names
        :param ban_codes: ignore subdomains which respond with these codes via HTTP
        :param ban_regex: ignore subdomains which respond with body matching this regular expression via HTTP
        """
        self.rep_log('==========\nSearching for the subdomains of %s' % self.host)
        wordlist, threads_num = open(words), int(threads)
        try:
            self.ban_codes = ban_codes.split(',')
        except:
            self.ban_codes = []
        self.ban_regex = ban_regex
        self.subs = [x.strip() for x in wordlist]
        words_num = len(self.subs)

        self.rep_log('%s names loaded. Starting %s threads' % (words_num, threads_num))
        threads, i, self.checked_subs = [], 0, 0

        blocks = words_num // threads_num
        while i < threads_num:
            a = i * blocks
            b = words_num if i == threads_num - 1 else a + blocks
            i += 1
            threads.append(threading.Thread(target=self.dobrute, args=(a, b)))
        i = 0

        while i < threads_num:
            threads[i].start()
            i += 1

    def dobrute(self, a, b):
        """
        A worker-method for WebHack.brutesubs()
        :param a: beginning of interval
        :param b: end of interval
        """
        for sub in self.subs[a: b]:
            if self.checked_subs % 1000 == 0 and self.checked_subs != 0:
                self.rep_log('%s names proceeded' % self.checked_subs)
            try:
                conn = httplib.HTTPConnection('%s.%s' % (sub, self.host), timeout=5)
                if self.ban_regex != '':
                    conn.request('GET', '/')
                else:
                    conn.request('HEAD', '/')
                res = conn.getresponse()
                self.cnt_reqs += 1
                if (str(res.status) not in self.ban_codes) and not (
                            self.ban_regex != None and re.search(self.ban_regex, res.read())):
                    domain = '%s.%s' % (sub, self.host)
                    self.known_subs.append(domain)
                    self.rep_log('Found: %s' % domain)
                conn.close()
            except (socket.gaierror, socket.herror):
                pass
            except (socket.timeout, socket.error):
                self.rep_log('Found: %s.%s' % (sub, self.host))
            self.checked_subs += 1

    def domxsstest(self, path):
        """
        Test if javascript-file matches some regular expressions, possibly indicating DOM XSS
        :param path: target path
        """
        self.restructure(path)
        self.rep_log('==========\nSearching for DOM-based XSS vulnerabilities in %s' % path)
        if self.known_urls[path]['html'] is None:
            self.known_urls[path]['html'], self.known_urls[path]['code'], self.known_urls[path]['hdrs'] = self.makereq(
                path)
        txt = self.known_urls[path]['html'].split('\n')
        for line, text in enumerate(txt):
            if re.search(
                        '((src|href|data|location|code|value|action)\s*["\'\]]*\s*\+?\s*=)|((replace|assign|navigate|' +
                        'getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|' +
                        'setTimeout|setInterval)\s*["\'\]]*\s*\()', text) or re.search(
                            '(location\s*[\[.])|([.\[]\s*["\']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|' +
                            'open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|' +
                            'parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)', text):
                info = 'DOM-based XSS. Line %s: %s' % (line, text) #tnx .mario for regexps
                self.rep_log(info)

    def minifuzz(self, path):
        """
        Rapid fuzzing of known parameters
        :param path: target path
        """
        self.restructure(path)
        fuzz_base = {
            '<hok>\'"koh\\ \r\ntest:tset;&\0': [
                {#patterns for response body
                 'SQL-injection': ['error.*sql', 'sql.*error'],
                 'PHP Error': ['warning.*php'],
                 'XSS': ['<hok>', '(\'[^k]*koh|[^"]*"koh)[^>]*>'], #second pattern is for xss in tag attribute
                },
                {#patterns for response headers
                 #'Internal Server Error' : [ '^HTTP/1.[01] 500' ],
                 'HTTP Response Splitting': ['\r\n?test']
                }
            ]
        }

        for payload in fuzz_base:
            for mode in ['get', 'post', 'cookie']:
                if len(self.known_urls[path]['args'][mode]) > 0:
                    self.rep_log('==========\nFuzzing %s-parameters' % mode.upper())
                    query = urlencode({x: payload for x in self.known_urls[path]['args'][mode]})
                    html, code, hdrs = self.gpcreq(path, query, mode)
                    if code == 500:
                        self.rep_log('Found Internal Server Error. Payload: %s' % query, path)
                    for vuln in fuzz_base[payload][0]: #checking response body
                        for pattern in fuzz_base[payload][0][vuln]:
                            if re.search(pattern, html, re.I | re.S):
                                self.rep_log('Found %s. Payload: %s' % (vuln, query), path)
                    for vuln in fuzz_base[payload][1]: #checking response headers
                        for pattern in fuzz_base[payload][1][vuln]:
                            if re.search(pattern, '\r\n'.join([' '.join((x, y)) for (x, y) in hdrs.items()]),
                                         re.I | re.S):
                                self.rep_log('Found %s. Payload: %s' % (vuln, query), path)

if __name__ == '__main__':
    PyWebHack()
