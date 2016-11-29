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
#
# Name: log.py
# Author : Dimeji Fayomi
# Created : 30 August 2016
# Last Modified :
# Version : 1.0
# Description: Manage logging for all RheaFlow applications

import logging
import logging.handlers
RHEAFLOWLOG = '/var/log/RheaFlow'
log = logging.getLogger('RheaFlow')
log.setLevel(logging.INFO)
StdOutHandler = logging.StreamHandler()
LogFileHandler = logging.handlers.RotatingFileHandler(RHEAFLOWLOG,
                                                      maxBytes=(1048576*5),
                                                      backupCount=7)
log_format = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
formatter = logging.Formatter(log_format, '%b %d %H:%M:%S')
LogFileHandler.setFormatter(formatter)
log.addHandler(LogFileHandler)
log.propagate = 0
