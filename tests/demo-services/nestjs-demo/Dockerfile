# Build context must be the repo root (needs the sibling library).
FROM node:24-alpine
WORKDIR /app/demo
# Clean package (the demo's own package.json references the workspace lib, which
# is not on the registry). Install the real third-party deps + the library's
# runtime deps + the NestJS HTTP platform, plus TypeScript to compile the demo.
RUN npm init -y >/dev/null && \
    npm install --no-audit --no-fund express js-yaml jose axios kafkajs \
      @nestjs/microservices@^11 @kafkajs/confluent-schema-registry \
      simple-oauth2 p-retry@^8 @nestjs/common@^11 @nestjs/core@^11 \
      @nestjs/platform-express@^11 reflect-metadata rxjs \
      typescript@^6 @types/node@^24
# Place the prebuilt library as a real package (not a symlink) so its internal
# requires resolve against the node_modules above.
COPY libraries/authz-nestjs/package.json node_modules/authz-nestjs/package.json
COPY libraries/authz-nestjs/dist node_modules/authz-nestjs/dist
COPY tests/demo-services/nestjs-demo/tsconfig.json ./
COPY tests/demo-services/nestjs-demo/src ./src
COPY tests/demo-services/nestjs-demo/authorization.yaml ./
# Compile the NestJS app (decorators + metadata) to dist/.
RUN npx tsc -p tsconfig.json
EXPOSE 5001
CMD ["node", "dist/main.js"]
