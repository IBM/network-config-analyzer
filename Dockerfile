#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

# Using python:3.8-slim
FROM python@sha256:d82f9b8300f1ab29b3a940b1a2dcf4590db5213ed1053ea49b44898367d38cf3

RUN python -m pip install -U pip wheel setuptools
COPY requirements.txt /nca/
RUN pip install -r /nca/requirements.txt

RUN apt-get update && apt-get install curl -y

RUN curl -L "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" --output /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl

RUN curl -L https://github.com/projectcalico/calicoctl/releases/download/v3.3.1/calicoctl --output /usr/local/bin/calicoctl
RUN chmod +x /usr/local/bin/calicoctl

COPY network-config-analyzer/ /nca/

USER 9000

ENTRYPOINT ["python", "/nca/nca.py"]
