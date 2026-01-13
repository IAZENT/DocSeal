FROM ubuntu:24.04

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /home/docseal

COPY . /home/docseal

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-venv \
    python3.11-distutils \
    build-essential \
    libssl-dev \
    libffi-dev \
    ca-certificates \
    wget \
 && wget https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py \
 && python3.11 /tmp/get-pip.py \
 && ln -sf /usr/bin/python3.11 /usr/bin/python \
 && python -m pip install --upgrade pip \
 && if [ -f requirements.txt ]; then python -m pip install --no-cache-dir -r requirements.txt; fi \
 && python -m pip install --no-cache-dir . \
 && apt-get purge -y build-essential wget \
 && apt-get autoremove -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/get-pip.py

CMD ["/bin/bash"]
