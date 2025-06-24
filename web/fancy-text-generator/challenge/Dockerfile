FROM node:24-alpine

ENV PORT=1337

WORKDIR /app

COPY src .

RUN npm i

EXPOSE 1337

USER node

ENTRYPOINT ["node", "server.js"]
