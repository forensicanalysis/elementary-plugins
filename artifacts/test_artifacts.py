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
    return mkdata()


def mkdata():
    tmpdir = tempfile.mkdtemp()
    tmpdir = tmpdir.replace("/var/folders", "/private/var/folders") # Required for osx
    shutil.copytree(os.path.join("test", "data"), os.path.join(tmpdir, "data"))
    return os.path.join(tmpdir, "data")


def to_unix_path(p):
    path_unix = p
    if p[1] == ":":
        path_unix = "/" + p.lower()[0] + p[2:].replace("\\", "/")
    return path_unix


def test_docker(data):
    client = docker.from_env()

    # build image
    image_tag = "test_artifacts"
    image, _ = client.images.build(path="artifacts/", tag=image_tag)

    # run image
    store_path = os.path.abspath(os.path.join(data, "example.forensicstore"))
    store_path_unix = to_unix_path(store_path)
    import_path = os.path.abspath(os.path.join(data, "win10_mock.vhd"))
    import_path_unix = to_unix_path(import_path)
    volumes = {
        store_path_unix: {'bind': '/store', 'mode': 'rw'},
        import_path_unix: {'bind': '/transit', 'mode': 'ro'}
    }
    # plugin_dir: {'bind': '/plugins', 'mode': 'ro'}
    out = client.containers.run(image_tag, volumes=volumes, stderr=True).decode("ascii")
    print(out)

    # test results
    store = forensicstore.connect(store_path)
    items = list(store.all())
    store.close()

    assert len(items) == 8

    # cleanup
    try:
        shutil.rmtree(data)
    except PermissionError:
        pass


if __name__ == '__main__':
    d = mkdata()
    test_docker(d)
