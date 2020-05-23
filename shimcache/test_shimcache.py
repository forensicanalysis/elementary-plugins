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

import os
import shutil
import sys
import tempfile
from io import StringIO

import pytest
import shimcache


@pytest.fixture
def data():
    tmpdir = tempfile.mkdtemp()
    shutil.copyfile(
        os.path.join("test", "data", "example1.forensicstore"),
        os.path.join(tmpdir, "input.forensicstore"))
    return tmpdir


def test_shimcache(data):
    cwd = os.getcwd()
    os.chdir(data)

    temp_out = StringIO()

    # Replace default stdout (terminal) with our stream
    sys.stdout = temp_out

    shimcache.main(os.path.join(data, "input.forensicstore"))

    assert temp_out.getvalue().count("\n") == 391 + 1

    sys.stdout = sys.__stdout__
    os.chdir(cwd)
    shutil.rmtree(data)
