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

INPUT_IMAGE_SUBDIR = "input_dir"


@pytest.fixture
def tmp():
    return mkdata()


def mkdata():
    tmpdir = tempfile.mkdtemp()
    tmpdir = tmpdir.replace("/var/folders", "/private/var/folders")  # Required for osx
    os.mkdir(os.path.join(tmpdir, INPUT_IMAGE_SUBDIR))
    shutil.copyfile(os.path.join("test", "data", "win10_mock.vhd"),
                    os.path.join(tmpdir, INPUT_IMAGE_SUBDIR, "win10_mock.vhd"))
    return tmpdir


def to_unix_path(p):
    path_unix = p
    if p[1] == ":":
        path_unix = "/" + p.lower()[0] + p[2:].replace("\\", "/")
    return path_unix


def test_docker(tmp):
    client = docker.from_env()

    # build image
    image_tag = "test_artifacts"
    image, _ = client.images.build(path="import-image/", tag=image_tag)

    store = forensicstore.new(os.path.join(tmp, "input.forensicstore"))
    store.close()

    # run image
    store_path = os.path.abspath(tmp)
    store_path_unix = to_unix_path(store_path)
    import_path = os.path.abspath(os.path.join(tmp, INPUT_IMAGE_SUBDIR))
    import_path_unix = to_unix_path(import_path)
    volumes = {
        store_path_unix: {'bind': '/elementary', 'mode': 'rw'},
        import_path_unix: {'bind': '/elementary/' + INPUT_IMAGE_SUBDIR, 'mode': 'ro'}
    }
    container = client.containers.run(
        image_tag,
        command=["--input-file", "win10_mock.vhd"],
        volumes=volumes,
        detach=True,
    )
    result = container.wait()
    out = container.logs()
    container.remove()
    print(out.decode("utf-8"))

    assert result["StatusCode"] == 0

    # test results
    store = forensicstore.open(os.path.join(store_path, "input.forensicstore"))
    items = list(store.all())
    store.close()

    # shutil.copyfile(os.path.join(store_path, "input.forensicstore"), "./input.forensicstore")
    assert len(items) == 1832

    # cleanup
    try:
        shutil.rmtree(tmp)
    except PermissionError:
        pass


if __name__ == '__main__':
    d = mkdata()
    test_docker(d)
