FROM python:3.8-alpine

RUN apk add build-base libffi-dev

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
COPY . /usr/src/app/

RUN pip3 install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "/usr/src/app/kerbmon.py"]
CMD ["-h"]
