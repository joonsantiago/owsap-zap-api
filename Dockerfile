FROM python:3.10.12

COPY requirements.txt /app/
WORKDIR /app

RUN apt update && \
    apt install --no-install-recommends -y build-essential gcc libgl1 libglib2.0-0 ffmpeg
RUN pip install --upgrade pip setuptools && \
    pip install --no-cache-dir -r requirements.txt

COPY . /app
EXPOSE 8000

CMD fastapi run --workers 4 main.py