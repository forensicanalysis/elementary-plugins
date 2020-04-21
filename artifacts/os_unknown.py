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
""" Base implementation for unknown systems, does nothing besides storing vars (see base class) """

from os_base import OperatingSystemBase


class UnknownOS(OperatingSystemBase):
    """ Do nothing """
    def get_os_name(self):
        return None  # since we do not know anything about the OS, do not restrict loading artifacts

    def get_registry(self):
        return None
