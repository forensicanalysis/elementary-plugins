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
""" Contains the base class for different operating systems """
import logging
from typing import Optional

from abc import abstractmethod, ABCMeta

from dfwinreg.registry import WinRegistry

LOGGER = logging.getLogger(__name__)


class OperatingSystemBase(object, metaclass=ABCMeta):
    """ All Operating System modules have to follow this interface to work with the ArtifactResolver """

    @abstractmethod
    def get_os_name(self) -> str:
        """ Return the name of the Operating System, e.g. 'Windows' """

    @abstractmethod
    def get_registry(self) -> Optional[WinRegistry]:
        """ Returns a dfWinReg WinRegistry to access the OS' registry or None if unsupported """

