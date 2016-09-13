#!/usr/bin/env python
#-*- coding:utf-8 -*-
#
# Copyright (C) 2016 Oladimeji Fayomi, University of Waikato.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages
from os import path

with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()


setup(
    name='rheaflow',
    version='0.0.1',
    description='Software defined network router',
    long_description=readme,
    author='Oladimeji Fayomi',
    author_email='olafayomi@gmail.com',
    url='https://github.com/wandsdn/rheaflow',
    license=license,
    packages=find_packages(exclude=['docs', 'tests']),
    install_requires=(
       'eventlet',
       'netaddr',
       'PyYAML',
       'pyroute2',
       'ryu'
    ),
    data_files=[('etc/ryu/', ['etc/ryu/config.yaml']),
                ('etc/ryu/', ['etc/ryu/ryu.conf']),
                ('bin/', ['rheaflow/RheaManager']),
                ('/etc/systemd/system/', ['etc/systemd/rheaflow.service']),
                ('/etc/systemd/system/', ['etc/systemd/netlinkprocessor.service'])],
    classifiers=[
       'License :: OSI Approved :: Apache License, Version 2.0',
       'Programming Language :: Python',
       'Operating System :: POSIX',
       'Topic :: Software Defined Networking',
       'Topic :: Network Programming',
       'Intended Audience :: Developers',
       'Development Status :: 4 - Beta'
    ])

