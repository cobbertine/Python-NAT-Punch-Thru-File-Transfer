FROM python:3.8.5-alpine3.11
RUN apk add gcc musl-dev python3-dev libffi-dev openssl-dev
RUN pip3 install pipenv
WORKDIR ~/NAPUFIT/
COPY Pipfile* ./
RUN pipenv install --ignore-pipfile
COPY . .
WORKDIR docker_app/
ENTRYPOINT [ "pipenv", "run", "python3", "web_interface.py" ]