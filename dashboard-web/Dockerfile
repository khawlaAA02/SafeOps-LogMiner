FROM node:18-alpine AS build
WORKDIR /app

ARG VITE_API_BASE
ARG VITE_REPORT_BASE
ENV VITE_API_BASE=$VITE_API_BASE
ENV VITE_REPORT_BASE=$VITE_REPORT_BASE

COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
