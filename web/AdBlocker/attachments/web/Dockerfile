FROM alpine:3.21.3

WORKDIR /usr/app

RUN apk add --no-cache \
    nodejs \
    npm \
    chromium \
    chromium-chromedriver \
    xterm

COPY package.json ./

RUN npm install

COPY . .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN adduser -D -u 1337 ctfuser && \
    chown -R ctfuser:ctfuser /usr/app && \
    chown ctfuser:ctfuser /entrypoint.sh

USER ctfuser

CMD ["/entrypoint.sh"] 