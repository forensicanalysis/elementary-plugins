# Copyright (c) 2020 Siemens AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Author(s): Jonas Plum

FROM python:3.9

ADD requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

WORKDIR /
ADD https://github.com/Neo23x0/sigma/archive/0.17.0.zip /sigma
RUN unzip /sigma

ADD . /app/
RUN mkdir -p /elementary/rules
RUN mv /sigma-0.17.0/rules/* /elementary/rules

RUN chmod +x /app/analyse_forensicstore.py

WORKDIR /store
ENTRYPOINT ["python", "/app/analyse_forensicstore.py"]

LABEL short="Process eventlogs with sigma"
LABEL parameter='\
{\
    "properties": {\
        "rules":{"type":"string","description":"Input yara rules directory"}\
    }\
}'
LABEL header="name,level,time,event.System.Computer,event.System.EventRecordID,event.System.EventID.Value,event.System.Level,event.System.Channel,event.System.Provider.Name"
