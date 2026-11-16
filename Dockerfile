FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000 \
    HOME=/home/user

RUN useradd -m -u 1000 -s /bin/bash user && \
    mkdir -p /home/user/app && \
    chown -R user:user /home/user

WORKDIR /home/user/app
COPY --chown=user:user app.py /home/user/app/app.py

USER 1000
EXPOSE 10000

HEALTHCHECK --interval=60s --timeout=5s --start-period=15s --retries=3 \
    CMD python3 -c "import os, urllib.request; p = os.environ.get('PORT', '10000'); urllib.request.urlopen(f'http://127.0.0.1:{p}/health', timeout=4).read()" || exit 1

ENTRYPOINT ["python3", "/home/user/app/app.py"]
