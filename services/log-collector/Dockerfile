FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
ENV NODE_ENV=production
RUN npm ci --omit=dev && npm cache clean --force

COPY . .

# user non-root
RUN addgroup -S app && adduser -S app -G app
USER app

EXPOSE 3001

# Healthcheck sans curl/wget: on utilise node
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3001/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["npm", "start"]
