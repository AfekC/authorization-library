import { All, Controller, NotFoundException } from "@nestjs/common";

/**
 * Catch-all so the global AuthzGuard runs on EVERY path — matching Spring's
 * servlet-level global filter. Without this, NestJS would 404 an unmapped path
 * before any authorization decision; here the guard runs first and denies
 * (no matching rule -> 403). Registered last so real routes take precedence.
 * If the guard *allows* (e.g. a public rule on an unmapped path), it's a genuine 404.
 */
@Controller()
export class FallbackController {
  @All("*path")
  fallback(): never {
    throw new NotFoundException();
  }
}
