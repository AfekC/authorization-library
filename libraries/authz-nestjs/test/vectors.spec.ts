import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { AuthorizationEngine } from "../src/decision-engine/engine.js";
import { PermissionCache } from "../src/permission-cache/cache.js";
import { AuthType, RuleInput } from "../src/rule-config/types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface DecisionVector {
  name: string;
  rules: RuleInput[];
  roleCache?: Record<string, string[]>;
  request?: {
    method: string;
    path: string;
    authType: AuthType;
    role?: string;
    serviceName?: string;
  };
  expected?: "ALLOW" | "DENY";
  expectCompileError?: boolean;
  reason?: string;
}

const VECTOR_DIR = path.resolve(
  __dirname,
  "../../../docs/contracts/test-vectors",
);

function loadVectors(): { file: string; vectors: DecisionVector[] }[] {
  const files = fs
    .readdirSync(VECTOR_DIR)
    .filter((f) => f.endsWith(".vectors.json"));
  return files.map((file) => ({
    file,
    vectors: JSON.parse(
      fs.readFileSync(path.join(VECTOR_DIR, file), "utf8"),
    ) as DecisionVector[],
  }));
}

describe("shared test vectors", () => {
  const groups = loadVectors();

  it("finds vector files", () => {
    expect(groups.length).toBeGreaterThan(0);
  });

  for (const { file, vectors } of groups) {
    describe(file, () => {
      for (const v of vectors) {
        it(v.name, () => {
          if (v.expectCompileError) {
            expect(() => AuthorizationEngine.compile(v.rules)).toThrow();
            return;
          }
          const engine = AuthorizationEngine.compile(v.rules);
          const cache = new PermissionCache(v.roleCache ?? {});
          const result = engine.authorize(v.request!, cache);
          expect(result).toBe(v.expected);
        });
      }
    });
  }
});
