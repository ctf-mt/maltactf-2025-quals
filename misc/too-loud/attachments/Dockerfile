FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends socat wget && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/.cache/whisper

RUN wget -q \
      https://openaipublic.azureedge.net/main/whisper/models/65147644a518d12f04e32d6f3b26facc3f8dd46e5390956a9424a650c0ce22b9/tiny.pt \
      -O /root/.cache/whisper/tiny.pt && \
    wget -q \
      https://openaipublic.azureedge.net/main/whisper/models/9ecf779972d90ba49c06d968637d720dd632c55bbf19d441fb42bf17a411e794/small.pt \
      -O /root/.cache/whisper/small.pt

RUN pip install --no-cache-dir openai-whisper numpy

COPY rizz.py /opt/rizz.py
WORKDIR /opt

EXPOSE 1337

ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:python3 /opt/rizz.py"]