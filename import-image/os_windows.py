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
""" Windows-specific functionality to build a knowledge base using the Registry """
import logging
import os.path
import re

import dfvfs_helper
from dfwinreg import regf as regfile_impl
from dfwinreg import registry as dfwinreg_reg
from dfwinreg.interface import WinRegistryFileReader
from fs.errors import FSError, ResourceNotFound
from fs.tempfs import TempFS
from os_base import OperatingSystemBase

LOGGER = logging.getLogger(__name__)


class RegistryFileOpener(WinRegistryFileReader):
    """
    This is a callback class used by dfwinreg to open registry hive files.
    We are using dfvfs as the backend to open files within our image.
    To resolve system variables, we make use of the variable database of
    the WindowsSystem instance.
    """

    # pylint: disable=too-few-public-methods

    def __init__(self, dfvfs, partition, windows_system):
        super(RegistryFileOpener, self).__init__()
        self.dfvfs = dfvfs
        self.partition = partition
        self.not_present = set()
        self.open_handles = []
        self.tmpfs = TempFS()
        self.windows_system = windows_system
        # callbacks.register_on_job_end(self._cleanup_open_files)

    def _cleanup_open_files(self, __):
        for path, handle in self.open_handles:
            try:
                handle.close()
                self.tmpfs.remove(path)
            except (OSError, FSError) as err:
                LOGGER.warning("Error cleaning up %s: %s", path, err)
        self.tmpfs.close()

    def Open(self, path, ascii_codepage='cp1252'):
        LOGGER.info("open registry %s", path)
        """ Opens a path within the dfVFS volume """
        realpath = path.replace('\\', '/')
        if path in self.not_present:
            return None

        # check for variables and if we know them
        realpath = path
        for match in re.finditer('%[a-zA-Z0-9_]+%', path):
            key = match.group(0)
            val = self.windows_system.get_var(key)
            if val:
                realpath = realpath.replace(key, val)
            else:
                LOGGER.warning("Could not resolve variable %s", key)
                return None

        realpath = realpath.replace('\\', '/')
        if realpath.lower().startswith('c:/'):  # catch absolute paths
            realpath = '/' + realpath[3:]
        if not realpath[0] == '/':
            realpath = '/' + realpath

        if realpath in self.not_present:
            return None

        path_specs = list(self.dfvfs.find_paths([realpath], partitions=[self.partition]))
        if not path_specs:
            LOGGER.warning("Could not find requested registry hive %s [%s]", path, realpath)
            self.not_present.add(path)
            self.not_present.add(realpath)
            return None
        if len(path_specs) > 1:
            LOGGER.warning("Found multiple registry hives for query %s, using %s",
                           path, dfvfs_helper.reconstruct_full_path(path_specs[0]))

        # extract the file locally
        filename = realpath.replace('/', '_')
        dfvfs_helper.export_file(path_specs[0], self.tmpfs, filename)

        try:
            file_object = self.tmpfs.open(filename, 'rb')
        except ResourceNotFound:
            files = self.tmpfs.listdir("/")
            LOGGER.warning("Could not open registry hive %s [%s] (%s)", path, realpath, files)
            return None
        self.open_handles.append((filename, file_object))
        reg_file = regfile_impl.REGFWinRegistryFile(ascii_codepage=ascii_codepage)
        reg_file.Open(file_object)

        return reg_file


class WindowsSystem(OperatingSystemBase):
    """
    Class to extract and hold information and variables associated with one windows installation
    """

    def __init__(self, dfvfs, partition):
        """
        Creates a new WindowsSystem instance and extracts basic information
        :param dfvfs[DFVFSHelper]: DFVFSHelper-object to access data
        :param partition[PathSpec]: A DFVFS-PathSpec object identifying the root of the
                system partition
        """
        super(WindowsSystem, self).__init__()
        self.dfvfs = dfvfs
        self.partition = partition

        LOGGER.info("Creating new WindowsSystem for %s",
                    dfvfs_helper.reconstruct_full_path(partition))

        self.users = {}
        self.vars = {}
        self._read_system_infos()  # MUST be done first, since registry access needs %SystemRoot% to be set
        self._reg_reader = RegistryFileOpener(self.dfvfs, self.partition, self)
        self._registry = dfwinreg_reg.WinRegistry(registry_file_reader=self._reg_reader)
        self._read_users()  # get user accounts from registry

    def get_os_name(self):
        return 'Windows'

    def get_registry(self):
        return self._registry

    def set_var(self, key, value):
        """
        Set a variable in this system's database
        :param key[str]: The name of the variable, with or without enclosing '%'-symbols
        :param value[str]: The (new) value of the variable
        """
        key_clean = key.replace('%', '').replace('environ_', '').lower()
        if key_clean in self.vars:
            LOGGER.info("Overwriting already existing variable %s", key_clean)
        self.vars[key_clean] = value

    def get_var(self, key):
        """
        Retrieve the value of a variable from this system's variable database
        :param key[str]: The name of the variable, with or without enclosing '%'-symbols
        :return: The value of the variable or None if the variable is unknown
        """
        key_clean = key.replace('%', '').replace('environ_', '').lower()
        return self.vars.get(key_clean, None)

    def _read_users(self):
        """
        Reads the usernames and SIDs from the system registry and stores them
        See: https://www.lifewire.com/how-to-find-a-users-security-identifier-sid-in-windows-2625149
        """
        try:
            registry_key = self._registry.GetKeyByPath(
                'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList')
        except ResourceNotFound:
            LOGGER.error("Could not get SOFTWARE key for ProfileList")
            return
        if not registry_key:
            LOGGER.error("Could not get SOFTWARE key for ProfileList")
            return
        for subkey in registry_key.GetSubkeys():
            user = ''
            sid = subkey.name
            profilepath = ''
            for val in subkey.GetValues():
                if val.name == 'ProfileImagePath':
                    profilepath = val.GetDataAsObject()
                    user = profilepath.split('\\')[-1]
                    break

            LOGGER.info("Found user %s with SID: %s", user, sid)
            # strip (optional) drive letter and normalize path separator
            # note: ProfileImagePath can be 'C:\Users\Someone' OR '%Systemroot%\Something'
            rel_profilepath = profilepath.replace('\\', '/')
            if ':' in profilepath and profilepath[1] == ':':
                rel_profilepath = rel_profilepath[2:]
            self.users[sid] = {
                "sid": sid,
                "username": user,
                "userprofile": rel_profilepath,
                "homedir": rel_profilepath  # this is used in some artifacts
            }

    def _read_system_infos(self):
        """
        Determine some basic system information. We need this to bootstrap registry access.
        The rest of interesting system data can then be resolved with artifacts
        """
        # find %SystemRoot%
        systemroot = list(
            self.dfvfs.find_paths(['/Windows', '/WINNT'], partitions=[self.partition]))
        if not systemroot:
            raise RuntimeError("No windows directory found on %s" % (
                dfvfs_helper.reconstruct_full_path(self.partition)))
        if len(systemroot) > 1:
            LOGGER.warning("More than one installation of Windows detected? Using %s",
                           dfvfs_helper.reconstruct_full_path(systemroot[0]))
        path_str = dfvfs_helper.get_relative_path(systemroot[0])
        self.set_var("%SystemRoot%", path_str)

        # %SystemDrive% is always '/'
        self.set_var('%SystemDrive%', '/')
