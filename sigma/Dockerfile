FROM python:3.8

ADD requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

WORKDIR /
ADD https://github.com/Neo23x0/sigma/archive/0.16.0.zip /sigma
RUN unzip /sigma

ADD . /app/
RUN mv /sigma-0.16.0/rules/* /app/rules

RUN chmod +x /app/analyse_forensicstore.py

WORKDIR /store
ENTRYPOINT ["python", "/app/analyse_forensicstore.py"]

LABEL use="sigma" short="Process eventlogs with sigma"
