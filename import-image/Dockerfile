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
# Author(s): Jonas Plum, Demian Kellermann

FROM log2timeline/plaso:20230311

RUN apt-get -y update \
    && apt-get -y install curl unzip python3-distutils python3-dfvfs python3-artifacts libregf-python3 \
    && apt-get clean \
    && rm -rf /var/cache/apt/* /var/lib/apt/lists/*

RUN rm -rf data /artifacts artifacts.zip artifacts.tar.gz \
    && curl --fail --silent --output artifacts.zip --location https://github.com/forensicanalysis/artifacts/archive/v0.6.4.zip \
    && unzip artifacts.zip \
    && mkdir /artifacts \
    && mv -fv artifacts-0.6.4/*.yaml /artifacts/

COPY requirements.txt .
RUN \
    curl --silent https://bootstrap.pypa.io/get-pip.py -o get-pip.py \
    && python3 get-pip.py \
    && rm get-pip.py \
    && pip3 install -U pip \
    && pip3 install -r requirements.txt

COPY . /app
ENTRYPOINT ["python3", "/app/main_cmd.py"]

LABEL short="Import images"
LABEL parameter='\
{\
    "properties": {\
        "artifacts-dir": {"type": "string","description": "Directory with artifact definitions"},\
        "input-dir": {"type": "string","description": "Directory containing input image data"},\
        "input-file": {"type": "string","description": "Filename of input image (relative to input-dir)"},\
        "artifact": {"type": "string","description": "Artifact(s) to extract, comma-separated"},\
        "partition-zips": {"type": "boolean", "description": "Process multiple zip archives as if they were partitions"},\
        "verbose": {"type": "boolean", "description": "Enable verbose logging"},\
        "keyfile": {"type": "string", "description": "Filename of decryption keys to use (relative to input-dir)"}\
    },\
    "required": ["input-dir", "input-file"]\
}'
