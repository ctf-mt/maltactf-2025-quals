FROM busybox:1.37

RUN adduser -D static
USER static
WORKDIR /home/static

COPY dist .

RUN echo '.json:application/json' > httpd.conf
RUN echo '.wal:application/zip' >> httpd.conf
CMD ["busybox", "httpd", "-f", "-v", "-p", "1337", "-c", "httpd.conf"]