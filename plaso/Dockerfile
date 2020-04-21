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

FROM log2timeline/plaso:20200227


RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install -v forensicstore

RUN echo "from plaso.output import forensicstore" >> /usr/lib/python3/dist-packages/plaso/output/__init__.py
RUN echo "from plaso.cli.helpers import forensicstore_output" >> /usr/lib/python3/dist-packages/plaso/cli/helpers/__init__.py

ADD plaso_forensicstore.py /usr/lib/python3/dist-packages/plaso/output/forensicstore.py
ADD plaso_forensicstore_output.py /usr/lib/python3/dist-packages/plaso/cli/helpers/forensicstore_output.py
ADD entry.py /entry.py
RUN chmod +x /entry.py

WORKDIR /store
ENTRYPOINT ["python3", "/entry.py"]
# ENTRYPOINT ["/bin/sh", "-c", "mkdir -p Plaso && log2timeline.py --status_view none --logfile test.log Plaso/events.plaso /store/WindowsDeviceSetup && psort.py --status_view none -o forensicstore -w /store/ Plaso/events.plaso"]

LABEL use="plaso" short="Process with plaso"