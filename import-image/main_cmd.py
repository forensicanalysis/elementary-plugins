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

from pyartifacts import Registry
from dfvfs_helper import encryption_handlers
from artifact_collector import ArtifactExtractor
import forensicstore

LOGGER = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Process forensic images and extract artifacts")
    parser.add_argument(
        "--partition-zips",
        dest="zip_mode",
        action="store_true",
        help="Use zip processing mode, each containing files from one partition"
    )
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
        help="Output forensicstore"
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
        nargs='+',
        dest="input_evidence",
        help="Input file(s) (or folders) to process"
    )
    parser.add_argument('-v', '--verbose', action='count', default=0)
    my_args, _ = parser.parse_known_args(sys.argv[1:])
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
        # do we have a key list for decryption?
        encryption_keys = []
        if self.args.keyfile:
            with open(self.args.keyfile, 'r') as keyfile:
                encryption_keys = encryption_handlers.read_key_list(keyfile)

        extractor = None
        # find the store file inside the input directory
        files = sorted(os.listdir(self.args.output_dir))
        store_file = next(f for f in files if os.path.isfile(os.path.join(self.args.output_dir, f)))
        store_file = os.path.join(self.args.output_dir, store_file)
        print("Using output forensicstore:", store_file)
        store = forensicstore.open(store_file)
        try:
            handler = encryption_handlers.ConsoleEncryptionHandler(encryption_keys)
            extractor = ArtifactExtractor(self.args.input_evidence, store,
                                          self.artifact_registry, handler, self.args.zip_mode)
            for artifact in self.args.artifact_names:
                print("Extract %s" % artifact)
                extractor.extract_artifact(artifact)
        except Exception as error:
            LOGGER.exception("Uncaught exception during job: %s", error)
        finally:
            store.close()
            if extractor:
                extractor.clean_up()


def cmd_mode(args):
    if not os.path.isdir(args.artifacts_path):
        print(f"Not a directory: {args.artifacts_path}")
        sys.exit(1)
    for infile in args.input_evidence:
        if not os.path.exists(infile):
            print(f"Input does not exist: {infile}")
            sys.exit(1)
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels)-1, args.verbose)]
    logging.basicConfig(format="[%(asctime)s] %(message)s", datefmt='%Y-%m-%d %H:%M:%S', level=level)
    logging.getLogger('dfvfs_helper.dfvfs_helper').setLevel(logging.ERROR)
    extractor = ArtifactExtractionCommand(args)
    extractor.run()


if __name__ == '__main__':
    a = parse_args()
    cmd_mode(a)
