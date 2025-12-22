FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

RUN mkdir -p /app/reports

EXPOSE 3006
CMD ["node", "index.js"]
