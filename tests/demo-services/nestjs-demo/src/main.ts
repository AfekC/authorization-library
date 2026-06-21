import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module.js";
import { authzKafkaOptions } from "authz-nestjs";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const brokers = (process.env.KAFKA_BROKERS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (brokers.length > 0) {
    app.connectMicroservice(
      authzKafkaOptions({
        brokers,
        schemaRegistryUrl: process.env.SCHEMA_REGISTRY_URL || "http://localhost:8081",
      }),
    );
    await app.startAllMicroservices();
  }

  const port = process.env.PORT || 5001;
  await app.listen(port);
  console.log(`nestjs-demo (NestJS) listening on :${port}`);
}

bootstrap().catch((e) => {
  console.error(e);
  process.exit(1);
});
