# Build context must be the repo root (needs the sibling library).
FROM node:22-alpine
WORKDIR /app/demo
COPY libraries/authz-nestjs/vendor/hatraa-otel-ts-7.0.11.tgz /tmp/hatraa-otel-ts-7.0.11.tgz
# Clean package (the demo's own package.json references the workspace lib, which
# is not on the registry). Install only the real third-party deps + the library's
# runtime deps so the library (copied as a real package below) resolves them.
RUN npm init -y >/dev/null && \
    npm install --omit=dev --no-audit --no-fund express js-yaml jose axios kafkajs \
      simple-oauth2 p-retry@^4 @nestjs/common@^11 @nestjs/core@^11 \
      reflect-metadata rxjs /tmp/hatraa-otel-ts-7.0.11.tgz
# Place the prebuilt library as a real package (not a symlink) so its internal
# requires resolve against the node_modules above.
COPY libraries/authz-nestjs/package.json node_modules/authz-nestjs/package.json
COPY libraries/authz-nestjs/dist node_modules/authz-nestjs/dist
COPY tests/demo-services/nestjs-demo/src ./src
COPY tests/demo-services/nestjs-demo/authorization.yaml ./
EXPOSE 5001
CMD ["node", "src/main.js"]
