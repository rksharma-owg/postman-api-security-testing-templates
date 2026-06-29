
FROM node:20-alpine
WORKDIR /workspace
COPY package*.json ./
RUN npm install
COPY . .
ENTRYPOINT ["npx", "newman"]
