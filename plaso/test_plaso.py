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
import tempfile

import docker
import forensicstore
import pytest


@pytest.fixture
def data():
    tmpdir = tempfile.mkdtemp()
    shutil.copyfile(
        os.path.join("test", "data", "example1.forensicstore"),
        os.path.join(tmpdir, "input.forensicstore"))
    tmpdir = tmpdir.replace("/var/folders", "/private/var/folders")  # Required for osx
    return tmpdir


def test_docker(data):
    client = docker.from_env()

    # build image
    image_tag = "test_docker"
    image, _ = client.images.build(path="plaso/", tag=image_tag)

    # run image
    store_path = os.path.abspath(os.path.join(data, "input.forensicstore"))
    store_path_unix = store_path
    if store_path[1] == ":":
        store_path_unix = "/" + store_path.lower()[0] + store_path[2:].replace("\\", "/")
    volumes = {store_path_unix: {'bind': '/elementary/input.forensicstore', 'mode': 'rw'}}
    output = client.containers.run(image_tag,
                                   command=["--filter", "artifact=WindowsDeviceSetup", "input.forensicstore"],
                                   volumes=volumes,
                                   stderr=True, stdout=True)
    print(output)

    # test results
    store = forensicstore.open(store_path)
    items = list(store.select([{"type": "event"}]))
    store.close()
    assert len(items) == 69

    # cleanup
    try:
        shutil.rmtree(data)
    except PermissionError:
        pass


if __name__ == '__main__':
    d = data()
    test_docker(d)
