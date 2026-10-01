FROM node:20-slim
WORKDIR /app
RUN npm install express@4.19.2 >/dev/null 2>&1
COPY server.js .
EXPOSE 3100
CMD ["node", "server.js"]
