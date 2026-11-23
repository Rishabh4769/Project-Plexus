# PLEXUS frontend — Vite build served by nginx, which reverse-proxies
# /api/* and /ws/* to the backend service.
#
# Build context is the frontend/ directory (see docker-compose.yml):
#   docker build -f frontend/Dockerfile frontend/
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . ./
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
