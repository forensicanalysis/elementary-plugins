#!/usr/bin/env python
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
# Author(s): Demian Kellermann
""" Glue logic to enable command line mode """
# pylint: disable=missing-class-docstring,missing-function-docstring

import argparse
import logging
import os
import sys

import encryption_handlers
from artifact_collector import ArtifactExtractor
from pyartifacts import Registry

LOGGER = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Process forensic images and extract artifacts")
    parser.add_argument(
        "-a",
        "--artifacts-path",
        default='artifacts',
        dest="artifacts_path",
        help="Path where to search for artifact definitions"
    )
    parser.add_argument(
        "-k",
        "--keys",
        dest="keyfile",
        help="Keyfile for decryption"
    )
    parser.add_argument(
        "-d",
        "--dir",
        dest="output_dir",
        help="Output location (will be created)"
    )
    parser.add_argument(
        "-e",
        "--extract",
        nargs='+',
        dest="artifact_names",
        help="Which artifact to extract"
    )
    parser.add_argument(
        "-i",
        "--input",
        # nargs='+',
        dest="input_evidence",
        help="Input file(s) (or folders) to process"
    )
    parser.add_argument(
        "forensicstores",
        nargs='+',
        help="Input forensicstore"
    )
    parser.add_argument('-v', '--verbose', action='count', default=0)
    my_args, un = parser.parse_known_args(sys.argv[1:])
    if not all([my_args.input_evidence, my_args.artifact_names]):
        parser.error("The following arguments are required: -e/--extract, -i/--input")
    return my_args


class ArtifactExtractionCommand:
    # pylint: disable=too-few-public-methods

    def __init__(self, args):
        self.artifact_registry = Registry()
        self.artifact_registry.read_folder(args.artifacts_path)
        if not self.artifact_registry.artifacts:
            LOGGER.warning("Could not read any artifact definition from %s", args.artifacts_path)
        artifact_names = list([a.name for a in self.artifact_registry.artifacts.values()])
        artifact_names.sort()
        self.args = args

    def run(self):
        # create output evidence folder using pyfs
        # os.makedirs(self.args.output_dir, exist_ok=True)

        # do we have a key list for decryption?
        encryption_keys = []
        if self.args.keyfile:
            with open(self.args.keyfile, 'r') as keyfile:
                encryption_keys = encryption_handlers.read_key_list(keyfile)

        extractor = None
        try:
            handler = encryption_handlers.ConsoleEncryptionHandler(encryption_keys)
            in_evidence = [self.args.input_evidence]  # f for f in self.args.input_evidence if f]

            in_files = []
            for f in in_evidence:
                for root, dirs, files in os.walk(f):
                    for name in files:
                        in_files.append(os.path.join(root, name))
            for store in self.args.forensicstores:
                extractor = ArtifactExtractor(in_files, os.path.join(self.args.output_dir, os.path.basename(store)),
                                              self.artifact_registry, handler)
                for artifact in self.args.artifact_names:
                    print("Extract %s" % artifact)
                    extractor.extract_artifact(artifact)
        except Exception as error:
            LOGGER.exception("Uncaught exception during job: %s", error)
        finally:
            if extractor:
                extractor.clean_up()


def cmd_mode(args):
    if not os.path.isdir(args.artifacts_path):
        print(f"Not a directory: {args.artifacts_path}")
        sys.exit(1)
    if not os.path.exists(args.input_evidence):
        print(f"Input does not exist: {args.input_evidence}")
        sys.exit(1)
    # levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = logging.DEBUG  # levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt='%Y-%m-%d %H:%M:%S', level=level)
    logging.getLogger('dfvfs_helper.dfvfs_helper').setLevel(logging.ERROR)
    extractor = ArtifactExtractionCommand(args)
    extractor.run()


if __name__ == '__main__':
    a = parse_args()
    print(a)
    cmd_mode(a)
