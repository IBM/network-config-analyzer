#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

# Using python:3.8-slim
FROM python@sha256:726098870bb14355cb12572764a3be191b42f8b15947d97affe3b8ec6a7a446e

COPY requirements.txt /nca/
RUN python -m pip install -U pip wheel setuptools && pip install -r /nca/requirements.txt

RUN apt-get update && apt-get install curl -y graphviz && rm -rf /var/lib/apt/lists

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
