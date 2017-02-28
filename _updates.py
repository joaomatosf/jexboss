# -*- coding: utf-8 -*-
"""
Module for managing updates to the JexBoss
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

import jexboss
from sys import version_info
import os
import shutil
from zipfile import ZipFile
import traceback
import logging, datetime
logging.captureWarnings(True)
FORMAT = "%(asctime)s (%(levelname)s): %(message)s"
logging.basicConfig(filename='jexboss_'+str(datetime.datetime.today().date())+'.log', format=FORMAT, level=logging.INFO)



global gl_http_pool


def set_http_pool(pool):
    global gl_http_pool
    gl_http_pool = pool


def auto_update():
    """
    Download and deploy the latest version
    :return: True if successfully updated
    """
    url = 'https://github.com/joaomatosf/jexboss/archive/master.zip'

    # backup of prior version7
    if os.path.exists('old_version'):
        shutil.rmtree('old_version')
    shutil.copytree(".", "." + os.path.sep + "old_version")

    # download and extract of new version
    jexboss.print_and_flush(GREEN + " * Downloading the new version from %s." %url +ENDC )
    r = gl_http_pool.request('GET', url)
    if r.status != 200:
        jexboss.print_and_flush(RED + " * Error: Could not complete the download of the new version. Check your internet connection." + ENDC)
        return False
    with open('master.zip', 'wb') as f:
        f.write(r.data)
    z = ZipFile('master.zip', 'r')
    jexboss.print_and_flush(GREEN + " * Extracting new version..." +ENDC)
    z.extractall(path='.')
    z.close()
    os.remove('master.zip')
    path_new_version = '.' + os.path.sep + 'jexboss-master'
    jexboss.print_and_flush(GREEN + " * Replacing the current version with the new version..."  + ENDC)
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
    jexboss.print_and_flush(BLUE + " * Checking for updates in: %s **\n" % url + ENDC)
    header = {"User-Agent": "Checking for updates"}

    try:
        r = gl_http_pool.request('GET', url, redirect=False, headers=header)
    except:
        jexboss.print_and_flush(RED + " * Error: Failed to check for updates ...\n" + ENDC)
        logging.warning("Failed to check for updates.", exc_info=traceback)
        return False

    if r.status != 200:
        jexboss.print_and_flush(RED + " * Error: could not check for updates ...\n" + ENDC)
        logging.warning("Failed to check for updates. HTTP Code: %s" % r.status)
        return False
    else:
        current_version = jexboss.__version__
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
            jexboss.print_and_flush (
            GREEN + BOLD + " * NEW VERSION AVAILABLE: JexBoss v%s (%s)\n" % (last_version, date_last_version) + ENDC +
            GREEN + "   * Link: %s\n" % link +
            GREEN + "   * Release notes:")
            for note in notes:
                jexboss.print_and_flush ("      %s" % note)
            return True
        else:
            return False