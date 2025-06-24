FROM nikolaik/python-nodejs:latest AS app
COPY main.py /srv/app/run
RUN chmod +x /srv/app/run
COPY cryptostuff.py /srv/app/
COPY flag.txt /srv/app/
COPY ./verifier /srv/app/verifier
RUN apt-get update
RUN apt-get install -y socat
ENTRYPOINT mount -t tmpfs none /tmp && socat TCP-LISTEN:1337,fork,reuseaddr,bind=0.0.0.0 EXEC:"/srv/app/run"
