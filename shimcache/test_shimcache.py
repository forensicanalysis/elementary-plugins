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
# Author(s): Jonas Plum

import importlib
import os
import shutil
import sys
import tempfile

import forensicstore
import pytest

import shimcache


@pytest.fixture
def data():
    tmpdir = tempfile.mkdtemp()
    shutil.copytree(os.path.join("test", "data"), os.path.join(tmpdir, "data"))
    return os.path.join(tmpdir, "data")


def test_shimcache(data):
    cwd = os.getcwd()
    os.chdir(os.path.join(data, "example1.forensicstore"))

    shimcache.main()

    store = forensicstore.connect(os.path.join(data, "example1.forensicstore"))
    items = list(store.select("shimcache"))
    store.close()
    assert len(items) == 391

    os.chdir(cwd)
    shutil.rmtree(data)
