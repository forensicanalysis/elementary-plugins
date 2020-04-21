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

"""The Forensicstore output module CLI arguments helper."""

from __future__ import unicode_literals

from plaso.lib import errors
from plaso.cli.helpers import interface
from plaso.cli.helpers import manager
from plaso.output import forensicstore


class ForensicstoreOutputArgumentsHelper(interface.ArgumentsHelper):
    """Forensicstore output module CLI arguments helper."""

    NAME = 'forensicstore'
    CATEGORY = 'output'
    DESCRIPTION = 'Argument helper for the Forensicstore output module.'

    # pylint: disable=arguments-differ
    @classmethod
    def ParseOptions(cls, options, output_module):
        """Parses and validates options.

        Args:
          options (argparse.Namespace): parser options.
          output_module (OutputModule): output module to configure.

        Raises:
          BadConfigObject: when the output module object is of the wrong type.
          BadConfigOption: when the output filename was not provided.
        """
        if not isinstance(output_module, forensicstore.ForensicstoreOutputModule):
            raise errors.BadConfigObject(
                'Output module is not an instance of ForensicstoreOutputModule')

        filename = getattr(options, 'write', None)
        if not filename:
            raise errors.BadConfigOption(
                'Output filename was not provided use "-w filename" to specify.')

        output_module.SetFilename(filename)


manager.ArgumentHelperManager.RegisterHelper(ForensicstoreOutputArgumentsHelper)
