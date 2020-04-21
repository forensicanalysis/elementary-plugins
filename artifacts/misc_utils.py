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
""" various helper methods """

import collections
import logging
import os
import os.path
from collections.abc import MutableSet
from datetime import datetime

import dfvfs_utils
import six

LOGGER = logging.getLogger(__name__)


class CasePreservingSet(MutableSet):
    """ https://stackoverflow.com/questions/27531211/how-to-get-case-insensitive-python-set """

    def __init__(self, *values):
        self._values = {}
        self._fold = str.casefold  # Python 3
        for val in values:
            self.add(val)

    def __repr__(self):
        return '<{}{} at {:x}>'.format(
            type(self).__name__, tuple(self._values.values()), id(self))

    def __contains__(self, value):
        return self._fold(value) in self._values

    def __iter__(self):
        return iter(self._values.values())

    def __len__(self):
        return len(self._values)

    def add(self, value):
        """ Add a value """
        self._values[self._fold(value)] = value

    def discard(self, value):
        """ Remove a value """
        try:
            del self._values[self._fold(value)]
        except KeyError:
            pass

    def update(self, values):
        """ Add multiple values """
        for value in values:
            self.add(value)


def ensure_dir(path, raise_=False):  # pragma: no cover
    """
    Ensure a given path is a directory by creating it if necessary and erroring out if it is a file
    :param path: [str]: A path
    :return: True if path is a folder or was created. False if it is a file
    """
    if not os.path.isdir(path):
        if os.path.exists(path):
            LOGGER.error("Output dir %s exists and is not a folder!")
            if raise_:
                raise RuntimeError("Output dir %s exists and is not a folder!")
            return False
        os.makedirs(path)
    return True


def iterable(arg):
    """
    We need to distinguish if a variable value is a list or a string. Since strings
    are also iterable in Python, this helper will decide if something is truely iterable
    """
    return isinstance(arg, collections.Iterable) and not isinstance(arg, six.string_types)


def get_file_infos(path_spec):
    """
    Returns metadata about files as a STIX 2.0 compliant dict.
    :param path_spec: PathSpec: dfVFS file_entry object
    :return: dict
    """

    file_entry = dfvfs_utils.pathspec_to_fileentry(path_spec)
    stat = file_entry.GetStat()
    if not stat:
        LOGGER.warning("Could not get stat object for %s", file_entry.name)

    entry = {
        "size": getattr(stat, 'size', 0),
        "name": file_entry.name,
        "type": file_entry.entry_type,
    }
    for time in [('atime', 'accessed'), ('mtime', 'modified'), ('crtime', 'created')]:
        secs = getattr(stat, time[0], 0)
        nanos = getattr(stat, time[0] + '_nano', 0)
        if secs and secs != 0:
            datetime_entry = datetime.utcfromtimestamp(secs)
            datetime_entry = datetime_entry.replace(microsecond=int(nanos / 10))
            entry[time[1]] = datetime_entry.isoformat(timespec='milliseconds') + 'Z'

    # the path is not part of STIX 2.0 for file objects, but is very useful to have,
    # so we make it a custom attribute
    entry["path"] = path_spec.location

    return entry
