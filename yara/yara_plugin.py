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

import json
import os
import sys

import forensicstore
import yara


def main(rules_dir):
    paths = {}
    for rule in os.listdir(rules_dir):
        if rule.endswith(".yar") or rule.endswith(".yara"):
            paths[rule] = os.path.join(rules_dir, rule)
    rules = yara.compile(filepaths=paths)
    store = forensicstore.open("/input/input.forensicstore")

    for path in store.fs.walk.files():
        with store.fs.open(path, mode='rb') as io:
            data = io.read()
            for match in rules.match(data=data):
                print(json.dumps({"type": "alert", "subtype": "yara", "file": path, "name": match.rule}))
    store.close()


if __name__ == '__main__':
    os.symlink("/input/forensicstore", "/input/input.forensicstore")
    if not os.path.exists("/input/input.forensicstore"):
        print("no forensicstore given")
        sys.exit(1)
    if os.path.exists("/input/rules"):
        main("/input/rules")
    else:
        main("/default_rules")
