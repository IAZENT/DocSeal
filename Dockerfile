FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /home/docseal
COPY . /home/docseal

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev \
 && python -m pip install --upgrade pip \
 && if [ -f requirements.txt ]; then python -m pip install --no-cache-dir -r requirements.txt; fi \
 && python -m pip install --no-cache-dir . \
 && apt-get purge -y build-essential \
 && apt-get autoremove -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
