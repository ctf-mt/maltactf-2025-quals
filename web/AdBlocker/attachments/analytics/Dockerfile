FROM node:18-alpine

WORKDIR /usr/app

COPY package.json ./
RUN npm install

COPY . .

RUN adduser -D -u 1338 analyticsuser && \
    chown -R analyticsuser:analyticsuser /usr/app

USER analyticsuser

EXPOSE 3000

CMD ["npm", "start"] 