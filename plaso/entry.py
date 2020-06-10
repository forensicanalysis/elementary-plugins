#!/usr/bin/env python3
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

import argparse
import logging
import os
import subprocess
import sys
import tempfile

import forensicstore

LOGGER = logging.getLogger(__name__)


class StoreDictKeyPair(argparse.Action):
    # pylint: disable=too-few-public-methods

    def __call__(self, parser, namespace, values, option_string=None):
        new_dict = {}
        for element in values.split(","):
            key, value = element.split("=")
            new_dict[key] = value
        if hasattr(namespace, self.dest):
            dict_list = getattr(namespace, self.dest)
            if dict_list is not None:
                dict_list.append(new_dict)
                setattr(namespace, self.dest, dict_list)
                return
        setattr(namespace, self.dest, [new_dict])


def main():
    parser = argparse.ArgumentParser(description='parse key pairs into a dictionary')
    parser.add_argument("--filter", dest="filter", action=StoreDictKeyPair, metavar="type=file,name=System.evtx...")
    args, _ = parser.parse_known_args(sys.argv[1:])

    if args.filter is None:
        args.filter = [{"type": "file"}]

    store = forensicstore.open("/input.forensicstore")
    files = []

    tmpdir = tempfile.mkdtemp()

    selected = list(store.select(args.filter))
    for item in selected:
        if "export_path" in item:
            dst_path = os.path.join(tmpdir, item["export_path"].strip("/"))
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            with store.load_file(item["export_path"]) as src, open(dst_path, "wb") as dest:
                dest.write(src.read())
                files.append(dst_path)
    store.close()

    os.makedirs("Plaso", exist_ok=True)
    for file in files:
        subprocess.run(
            ["log2timeline.py", "--status_view", "none", "--logfile", "test.log", "Plaso/events.plaso", file],
            check=True)

    # TODO: add logfile to forensicstore

    subprocess.run(["psort.py", "--status_view", "linear", "-o", "forensicstore", "-w", "/input.forensicstore", "Plaso/events.plaso"],
                   check=True)


if __name__ == '__main__':
    main()
