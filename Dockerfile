FROM python:3.11-slim AS builder
WORKDIR /home/docseal
COPY requirements.txt .
RUN apt-get update \
 && apt-get install -y build-essential libssl-dev libffi-dev \
 && python -m pip install --upgrade pip \
 && python -m pip install --prefix=/install --no-cache-dir -r requirements.txt \
 && apt-get purge -y build-essential \
 && apt-get autoremove -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

FROM python:3.11-slim
WORKDIR /home/docseal
COPY --from=builder /install /usr/local
COPY . .
CMD ["/bin/bash"]
