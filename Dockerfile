#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

# Using python:3.9-slim
FROM python@sha256:380d708853b1564b71ad3744a69895d552099f618df60741c5d4a9e9e65873b9

COPY requirements.txt /nca/
RUN python -m pip install -U pip wheel setuptools && pip install -r /nca/requirements.txt

RUN apt-get update && apt-get install -y curl graphviz && rm -rf /var/lib/apt/lists

RUN curl -L "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" --output /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

RUN curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && chmod 700 get_helm.sh \
    && ./get_helm.sh

RUN curl -L https://github.com/projectcalico/calicoctl/releases/download/v3.3.1/calicoctl --output /usr/local/bin/calicoctl \
    && chmod +x /usr/local/bin/calicoctl

RUN apt-get purge curl -y && apt-get autoremove -y

COPY nca/ /nca/

USER 9000

WORKDIR "/"
ENTRYPOINT ["python", "-m", "nca"]
