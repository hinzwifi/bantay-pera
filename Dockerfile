FROM node:20-slim

WORKDIR /app

# Install dependencies in server
COPY server/package*.json ./server/
WORKDIR /app/server
RUN npm ci --only=production

# Copy application files (node_modules excluded via .dockerignore)
WORKDIR /app
COPY data/ ./data/
COPY scrapers/ ./scrapers/
COPY server/ ./server/
COPY client/ ./client/

WORKDIR /app/server
EXPOSE 3000

CMD ["node", "index.js"]
