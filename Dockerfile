FROM python:3.9-slim

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r ./requirements/requirements.txt

CMD ["python", "-m", "hypercorn", "app:asgi_app"]
