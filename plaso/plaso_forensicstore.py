# Copyright (c) 2019 Siemens AG
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

"""Output module for the forensicstore format."""

from __future__ import unicode_literals

import forensicstore
from plaso.output import interface
from plaso.output import manager
from plaso.serializer import json_serializer


class ForensicstoreOutputModule(interface.OutputModule):
    """Output module for the forensicstore format."""

    NAME = 'forensicstore'
    DESCRIPTION = 'Output module that writes events into an forensicstore.'

    _JSON_SERIALIZER = json_serializer.JSONAttributeContainerSerializer

    def __init__(self, output_mediator):
        """Initializes the output module object.

        Args:
        output_mediator (OutputMediator): output mediator.

        Raises:
        ValueError: if the file handle is missing.
        """
        super(ForensicstoreOutputModule, self).__init__(output_mediator)
        self._store = None
        self._filename = None

    def _WriteSerializedDict(self, event, event_data, event_tag):
        """Writes an event, event data and event tag to serialized form.
        Args:
          event (EventObject): event.
          event_data (EventData): event data.
          event_tag (EventTag): event tag.
        Returns:
          dict[str, object]: JSON serialized objects.
        """
        event_data_json_dict = self._JSON_SERIALIZER.WriteSerializedDict(event_data)
        del event_data_json_dict['__container_type__']
        del event_data_json_dict['__type__']

        inode = event_data_json_dict.get('inode', None)
        if inode is None:
            event_data_json_dict['inode'] = 0

        try:
            message, _ = self._output_mediator.GetFormattedMessages(event_data)
            event_data_json_dict['message'] = message
        except errors.WrongFormatter:
            pass

        event_json_dict = self._JSON_SERIALIZER.WriteSerializedDict(event)
        event_json_dict['__container_type__'] = 'event'

        event_json_dict.update(event_data_json_dict)

        if event_tag:
            event_tag_json_dict = self._JSON_SERIALIZER.WriteSerializedDict(event_tag)

            event_json_dict['tag'] = event_tag_json_dict

        return event_json_dict

    def WriteEventBody(self, event, event_data, event_tag):
        """Writes event values to the output.

        Args:
        event (EventObject): event.
        event_data (EventData): event data.
        event_tag (EventTag): event tag.
        """
        json_dict = self._WriteSerializedDict(event, event_data, event_tag)
        json_dict["type"] = "event"
        self._store.insert(json_dict)

    def Open(self):
        """Connects to the database and creates the required tables.

        Raises:
          IOError: if the specified output file already exists.
          OSError: if the specified output file already exists.
          ValueError: if the filename is not set.
        """
        if not self._filename:
            raise ValueError('Missing filename.')

        self._store = forensicstore.connect(self._filename)

    def Close(self):
        """Disconnects from the database.

        This method will create the necessary indices and commit outstanding
        transactions before disconnecting.
        """
        self._store.close()

    def SetFilename(self, filename):
        """Sets the filename.

        Args:
          filename (str): the filename.
        """
        self._filename = filename


def IsLinearOutputModule(self):
    return False


manager.OutputManager.RegisterOutput(ForensicstoreOutputModule)
manager.OutputManager.IsLinearOutputModule = IsLinearOutputModule
