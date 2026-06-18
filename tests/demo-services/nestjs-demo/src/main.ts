import "reflect-metadata";
import { initObservability } from "authz-nestjs";

// OTel must be initialized before NestJS/HTTP modules are imported so that
// request auto-instrumentation can hook the runtime. Under ESM, static `import`
// statements are hoisted and evaluated before any top-level code, so NestJS/HTTP
// are pulled in via dynamic import() *after* initObservability() runs to preserve
// that ordering (CommonJS `require` ordering did this implicitly).
const OTEL_ENV = (process.env.ENV_NAME || process.env.ENVIRONMENT || "drill").toLowerCase();
initObservability({
  enabled: true,
  serviceName: process.env.SERVICE_NAME || "nestjs-demo",
  systemName: process.env.SYSTEM_NAME || process.env.SYSTEM || "auth-library",
  envName: OTEL_ENV as any,
  otelExporterOtlpEndpoint: process.env.OTEL_EXPORTER_OTLP_ENDPOINT,
});

async function bootstrap() {
  const { NestFactory } = await import("@nestjs/core");
  const { AppModule } = await import("./app.module.js");
  const app = await NestFactory.create(AppModule);
  const port = process.env.PORT || 5001;
  await app.listen(port);
  console.log(`nestjs-demo (NestJS) listening on :${port}`);
}

bootstrap().catch((e) => {
  console.error(e);
  process.exit(1);
});
