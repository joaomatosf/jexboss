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
from jexboss import __version
import os
import shutil
from zipfile import ZipFile

from urllib3 import disable_warnings, PoolManager
from urllib3.util.timeout import Timeout

disable_warnings()

timeout = Timeout(connect=3.0, read=6.0)
pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'


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
    print(BLUE + " * Checking for updates in: %s **\n" % url + ENDC)
    header = {"User-Agent": "Checking for updates"}
    r = pool.request('GET', url, redirect=False, headers=header)

    if r.status != 200:
        print(RED + " * Error: could not check for updates ...\n" + ENDC)
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
            GREEN + BOLD + " * NEW VERSION AVAILABLE: JexBoss v%s (%s)\n" % (last_version, date_last_version) + ENDC +
            GREEN + "   * Link: %s\n" % link +
            GREEN + "   * Release notes:")
            for note in notes:
                print ("      %s" % note)
            return True
        else:
            return False