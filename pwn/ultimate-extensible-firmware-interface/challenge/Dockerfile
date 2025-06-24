FROM gcr.io/kctf-docker/challenge@sha256:9f15314c26bd681a043557c9f136e7823414e9e662c08dde54d14a6bfd0b619f

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    qemu-system-x86 && \
    rm -rf /var/lib/apt/lists/*

COPY contents /home/user/contents
COPY OVMF.fd /home/user/
COPY run.sh /home/user/chal
RUN chmod +x /home/user/chal

CMD mount -t tmpfs none /tmp && \
    kctf_setup && \
    kctf_drop_privs \
    socat \
      TCP-LISTEN:1337,reuseaddr,fork \
      EXEC:"kctf_pow /home/user/chal"