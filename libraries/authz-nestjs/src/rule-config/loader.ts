import * as fs from "fs";
import * as yaml from "js-yaml";
import { ConfigError, RuleInput } from "./types.js";
import { compileRules } from "./compile.js";
import { AuthorizationEngine } from "../decision-engine/engine.js";

interface RawConfig {
  rules?: RuleInput[];
}

/**
 * Preprocess raw YAML text before parsing: replace bare `*` tokens that
 * appear inside YAML flow sequences (followed by optional whitespace then
 * `,` or `]`) with the quoted string `"*"`.
 *
 * js-yaml treats a bare `*` as an alias anchor reference, which either
 * throws a parse error or resolves to `null` — neither is what the author
 * intended.  Java's YamlLoader applies the identical regex substitution
 * (`\*(?=\s*[,\]])` → `"*"`) so both libraries accept the same YAML syntax
 * (N7 parity).
 */
function preprocessYaml(yamlText: string): string {
  return yamlText.replace(/\*(?=\s*[,\]])/g, '"*"');
}

/** Parse authorization.yaml text into a validated, compiled engine (fail-fast). */
export function loadAuthorizationConfig(yamlText: string): AuthorizationEngine {
  let parsed: unknown;
  try {
    parsed = yaml.load(preprocessYaml(yamlText));
  } catch (e) {
    throw new ConfigError(`authorization.yaml is not valid YAML: ${e}`);
  }
  if (!parsed || typeof parsed !== "object") {
    throw new ConfigError("authorization.yaml must be a mapping with 'rules'");
  }
  const cfg = parsed as RawConfig;
  if (!Array.isArray(cfg.rules)) {
    throw new ConfigError("authorization.yaml must contain a 'rules' list");
  }
  // compileRules validates + detects ambiguity; reuse it via the engine.
  compileRules(cfg.rules);
  return AuthorizationEngine.compile(cfg.rules);
}

/** Load + compile authorization.yaml from disk. */
export function loadAuthorizationFile(path: string): AuthorizationEngine {
  return loadAuthorizationConfig(fs.readFileSync(path, "utf8"));
}
