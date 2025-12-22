FROM node:18-alpine

WORKDIR /app

# Meilleur cache + installs reproductibles
COPY package*.json ./
RUN npm ci --omit=dev

# Copier le code
COPY . .

EXPOSE 3001

# Optionnel: bonne pratique (non-root)
# RUN addgroup -S app && adduser -S app -G app
# USER app

CMD ["npm", "start"]
