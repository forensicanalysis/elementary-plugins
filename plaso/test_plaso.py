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
    tmpdir = tmpdir.replace("/var/folders", "/private/var/folders") # Required for osx
    shutil.copytree(os.path.join("test", "data"), os.path.join(tmpdir, "data"))
    return os.path.join(tmpdir, "data")


def test_docker(data):
    client = docker.from_env()

    # build image
    image_tag = "test_docker"
    image, _ = client.images.build(path="plaso/", tag=image_tag)

    # run image
    store_path = os.path.abspath(os.path.join(data, "example1.forensicstore"))
    store_path_unix = store_path
    if store_path[1] == ":":
        store_path_unix = "/" + store_path.lower()[0] + store_path[2:].replace("\\", "/")
    volumes = {store_path_unix: {'bind': '/store', 'mode': 'rw'}}
    # plugin_dir: {'bind': '/plugins', 'mode': 'ro'}
    output = client.containers.run(image_tag, command=["--filter", "artifact=WindowsDeviceSetup"], volumes=volumes,
                                   stderr=True, stdout=True)
    print(output)

    # test results
    store = forensicstore.connect(store_path)
    items = list(store.select("event"))
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
