FROM node:20-alpine

WORKDIR /app

# Copy server package files and install
COPY server/package*.json ./server/
WORKDIR /app/server
RUN npm ci --only=production

# Copy application files
WORKDIR /app
COPY data/ ./data/
COPY scrapers/ ./scrapers/
COPY server/ ./server/
COPY client/ ./client/

# Compile SQLite database
RUN node -e "console.log('Compiling node ready...')"

WORKDIR /app/server
EXPOSE 3000

CMD ["node", "index.js"]
