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

import argparse
import json
import os
import sys

import forensicstore
import yara


def main(url, rules_dir):
    paths = {}
    for rule in os.listdir(rules_dir):
        paths[rule] = os.path.join(rules_dir, rule)
    rules = yara.compile(filepaths=paths)
    store = forensicstore.open(url)

    print(json.dumps({"header": ["file", "rule"]}))
    for path in store.fs.walk.files():
        with store.fs.open(path, mode='rb') as io:
            data = io.read()
            for match in rules.match(data=data):
                print(json.dumps({"type": "yara", "file": path, "rule": match.rule}))
    store.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="elementary run yara", description="Process yara rules", usage=argparse.SUPPRESS)
    parser.add_argument("forensicstore", help="Input forensicstore")
    parser.add_argument("--rules", help="Input yara rules directory", required=True)
    args, _ = parser.parse_known_args(sys.argv[1:])
    if not os.path.exists("/rules"):
        print("no rules given")
        sys.exit(1)
    main(os.path.join("/store", os.path.basename(args.forensicstore)), "/rules")
