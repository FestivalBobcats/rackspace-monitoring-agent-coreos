FROM stackbrew/ubuntu:xenial


RUN apt-get update && apt-get -y upgrade && apt-get -y install curl
RUN curl https://monitoring.api.rackspacecloud.com/pki/agent/linux.asc | apt-key add -
RUN echo "deb http://stable.packages.cloudmonitoring.rackspace.com/ubuntu-16.04-x86_64 cloudmonitoring main" > /etc/apt/sources.list.d/rackspace-monitoring-agent.list
RUN apt-get update && apt-get -y install libffi-dev libjpeg8-dev libssl-dev libxml2-dev libxslt-dev sysstat rackspace-monitoring-agent python-dev gcc python-pip vim

# Install Python
RUN pip install rackspace-monitoring-cli==0.7.2 requests

# Install script
COPY *.py /usr/lib/rackspace-monitoring-agent/plugins/
