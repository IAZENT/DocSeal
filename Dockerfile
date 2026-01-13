FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash docseal
USER docseal
WORKDIR /home/docseal

COPY requirements.txt .

RUN python -m venv venv \
 && . venv/bin/activate \
 && pip install --upgrade pip setuptools wheel \
 && pip install --no-cache-dir -r requirements.txt

COPY . .

RUN . venv/bin/activate \
 && pip install --no-cache-dir .

CMD ["/bin/bash"]
