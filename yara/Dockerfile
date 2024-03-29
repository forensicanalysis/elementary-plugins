# Copyright (c) 2020 Jonas Plum
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

FROM alpine:3.15

RUN apk add --no-cache python3-dev python3 py3-pip build-base
RUN apk add --no-cache openssl file jansson bison tini su-exec
RUN apk add --no-cache -t .build-deps \
  openssl-dev \
  jansson-dev \
  libc-dev \
  file-dev \
  automake \
  autoconf \
  libtool \
  flex \
  git

ADD requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt

RUN git clone  --branch v4.0.1 --recursive https://github.com/VirusTotal/yara-python
WORKDIR /yara-python
RUN python3 setup.py build --enable-magic --enable-cuckoo --enable-dotnet --enable-dex --enable-macho
RUN python3 setup.py install

WORKDIR /
ADD https://github.com/Neo23x0/signature-base/archive/master.zip /master.zip
RUN unzip /master.zip
RUN mkdir /default_rules
RUN mv /signature-base-master/yara/* /default_rules
RUN rm -f /default_rules/generic_anomalies.yar
RUN rm -f /default_rules/general_cloaking.yar
RUN rm -f /default_rules/thor_inverse_matches.yar
RUN rm -f /default_rules/yara_mixed_ext_vars.yar

ADD yara_plugin.py /yara_plugin.py
RUN chmod +x /yara_plugin.py

ENTRYPOINT ["python3", "/yara_plugin.py"]

LABEL short="Process files with yara"
LABEL parameter='\
{\
    "properties":{\
        "rules":{"type":"string","description":"Input yara rules directory","ispath":true}\
    }\
}'
LABEL header="file,rule"
