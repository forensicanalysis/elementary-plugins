# Copyright (c) 2020 Jonas Plum
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
def tmpdir():
    tmpdir = tempfile.mkdtemp()
    tmpdir = tmpdir.replace("/var/folders", "/private/var/folders")  # Required for osx
    shutil.copyfile(
        os.path.join("test", "data", "example1.forensicstore"),
        os.path.join(tmpdir, "input.forensicstore"))
    os.makedirs(os.path.join(tmpdir, "rules"))
    with open(os.path.join(tmpdir, "rules", "pf.yar"), "w+") as io:
        io.write("""rule Prefetch{strings: $magic = "MAM" condition: $magic}""")
    return tmpdir


def to_unix_path(p):
    path_unix = p
    if p[1] == ":":
        path_unix = "/" + p.lower()[0] + p[2:].replace("\\", "/")
    return path_unix


# def test_yara(tmpdir):
#     cwd = os.getcwd()
#     os.chdir(tmpdir)
#
#     temp_out = StringIO()
#
#     # Replace default stdout (terminal) with our stream
#     # sys.stdout = temp_out
#
#     yara_plugin.main(os.path.join(tmpdir, "input.forensicstore"), os.path.join(tmpdir, "rules"))
#
#     assert temp_out.getvalue().count("\n") == 391 + 1
#
#     sys.stdout = sys.__stdout__
#     os.chdir(cwd)
#     shutil.rmtree(tmpdir)


def test_docker(tmpdir):
    client = docker.from_env()

    # build image
    image_tag = "test_yara"
    image, _ = client.images.build(path="yara/", tag=image_tag)

    # run image
    store_path = os.path.abspath(os.path.join(tmpdir, "input.forensicstore"))
    store_path_unix = to_unix_path(store_path)
    rules_path = os.path.abspath(os.path.join(tmpdir, "rules"))
    rules_path_unix = to_unix_path(rules_path)
    volumes = {
        store_path_unix: {'bind': '/elementary/input.forensicstore', 'mode': 'rw'},
        rules_path_unix: {'bind': '/elementary/rules', 'mode': 'ro'}
    }
    out = client.containers.run(image_tag, command=["input.forensicstore", "--rules", ""], volumes=volumes, stderr=True)

    assert out.decode("ascii").count("\n") == 261 + 1

    # cleanup
    try:
        shutil.rmtree(tmpdir)
    except PermissionError:
        pass
