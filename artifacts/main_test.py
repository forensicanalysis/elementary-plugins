#!/usr/bin/env python
# Copyright (c) 2020 Siemens AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author(s): Demian Kellermann
""" Some basic tests for the extraction extractor """
# pylint: skip-file

import hashlib
import logging
import os
import shutil
from os.path import dirname, realpath, join, isdir

from forensicstore import ForensicStore

logging.getLogger('jsonlite.jsonlite').setLevel(logging.WARNING)

TEST_CASE_NAME = 'test_case'

CASES_LOCAL_PATH = realpath(join(dirname(realpath(__file__)), '..', 'test_images'))


def md5_file(file_path):
    CHUNK = 4096
    md5 = hashlib.md5()  # nosec
    with open(file_path, 'rb') as infile:
        data = infile.read(CHUNK)
        while data:
            md5.update(data)
            data = infile.read(CHUNK)
    return md5.hexdigest()


def teardown_function():
    """ Runs after every test and cleans output folder so the evidence can be recreated by the extractor """
    output_base = join(CASES_LOCAL_PATH, TEST_CASE_NAME)
    folders = [join(output_base, f) for f in os.listdir(output_base) if
               isdir(join(output_base, f)) and f.startswith('artifacts')]
    for folder in folders:
        shutil.rmtree(folder)


def find_store(local_path):
    store = None
    for root, dirs, files in os.walk(local_path):
        if root.endswith('.forensicstore'):
            assert store is None  # There is only one partition here
            store = ForensicStore(root)
    assert store is not None
    return store
