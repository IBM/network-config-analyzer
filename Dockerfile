#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

FROM python:3-alpine

COPY requirements.txt /nca/
RUN pip install -r /nca/requirements.txt

RUN apk add --no-cache curl

RUN curl -L https://storage.googleapis.com/kubernetes-release/release/v1.20.0/bin/linux/amd64/kubectl --output /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl

RUN curl -L https://github.com/projectcalico/calicoctl/releases/download/v3.3.1/calicoctl --output /usr/local/bin/calicoctl
RUN chmod +x /usr/local/bin/calicoctl

COPY network-config-analyzer/ /nca/

RUN addgroup -S ncagroup && adduser -S ncauser -G ncagroup
USER ncauser

ENTRYPOINT ["python", "nca/nca.py"]
