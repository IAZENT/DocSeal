FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev \
 && python -m pip install --upgrade pip setuptools wheel \
 && apt-get purge -y build-essential \
 && apt-get autoremove -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash docseal
USER docseal
WORKDIR /home/docseal

COPY requirements.txt .

RUN python -m pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -m pip install --no-cache-dir .

CMD ["/bin/bash"]
