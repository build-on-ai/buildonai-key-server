FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache curl

COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install --production

COPY server.js ./
COPY middleware ./middleware
COPY auth ./auth
COPY docs ./docs

ENV KEY_SERVER_PORT=3040 \
    KEY_SERVER_HOST=0.0.0.0

EXPOSE 3040

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${KEY_SERVER_PORT}/health || exit 1

CMD ["node", "server.js"]
