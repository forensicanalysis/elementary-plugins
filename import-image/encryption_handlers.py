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
""" Contains different implementation of the EncryptionHandler for various use cases """

import logging
import sys

import unicodecsv as csv
from dfvfs_helper import EncryptionHandler

LOGGER = logging.getLogger(__name__)


class ConsoleEncryptionHandler(EncryptionHandler):
    """ A handler for the command line """

    def __init__(self, keys):
        """
        Initializes the Handler
        :param keys: A list of encryption keys to try before asking: Must be in form of a tuple:
                     (key_type, key)
        """
        self.keys = keys
        self.keys_by_device = {}

    def unlock_volume(self, info, credentials):
        """ Tries to unlock a volume with given credentials """
        if info not in self.keys_by_device:
            self.keys_by_device[info] = [k for k in self.keys if k[0] in credentials]

        if self.keys_by_device[info]:
            next_key = self.keys_by_device[info].pop()
            return next_key

        credentials = credentials[:] + ['skip']
        print("Encrypted volume:", info)

        print('Supported credentials:')
        print('')
        for index, name in enumerate(credentials):
            print('  {0:d}. {1:s}'.format(index, name))
        print('')

        while True:
            print('Select a credential to unlock the volume: ', )
            # note: method "startup key" needs a filename to read, not a string
            # maybe implement this later
            input_line = sys.stdin.readline()
            input_line = input_line.strip()

            if input_line in credentials:
                credential_type = input_line
            else:
                try:
                    credential_type = int(input_line, 10)
                    credential_type = credentials[credential_type]
                except (IndexError, ValueError):
                    print('Unsupported credential: {0:s}'.format(input_line))
                    continue

            if credential_type == 'skip':
                return None, None

            getpass_string = 'Enter credential data: '
            credential_data = input(getpass_string)

            if credential_type == 'key':
                try:
                    credential_data = credential_data.decode('hex')
                except TypeError:
                    print('Unsupported credential data.')
                    continue
            print('')

            return credential_type, credential_data


def read_key_list(handle):
    """ Reads a key list from a ;-separated filehandle """
    encryption_keys = []
    key_csv = csv.reader(handle, delimiter=';', quoting=csv.QUOTE_ALL)
    for row in key_csv:
        if len(row) > 1:
            encryption_keys.append((row[0], row[1]))
        elif row:
            LOGGER.warning("Could not parse malformed password entry: %s", row)
    return encryption_keys
