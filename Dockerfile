FROM python:3.13-alpine

ENV APP_HOME=/usr/src/app

WORKDIR $APP_HOME
ADD . $APP_HOME

RUN pip install infoga-ng

ENTRYPOINT ["infoga"]
