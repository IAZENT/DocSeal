FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash docseal

USER docseal
WORKDIR /home/docseal

COPY requirements.txt .

RUN python -m venv /home/docseal/venv \
 && /home/docseal/venv/bin/pip install --upgrade pip setuptools wheel \
 && /home/docseal/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY . .

RUN /home/docseal/venv/bin/pip install --no-cache-dir .

ENV PATH="/home/docseal/venv/bin:$PATH"

CMD ["/bin/bash"]
