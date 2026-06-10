/** Authorization rule as authored in authorization.yaml. */
export type DecisionMode = "ANY" | "ALL";

export interface RuleInput {
  path: string;
  methods: string[];
  permissions?: string[];
  decision?: DecisionMode;
  allowedServices?: string[];
  /** public:true -> no validation, always ALLOW; mutually exclusive with the above. */
  public?: boolean;
}

export type SegmentKind = "literal" | "single" | "deep";

export interface Segment {
  kind: SegmentKind;
  /** Present only for literal segments. */
  value?: string;
}

/** A compiled, validated rule with precomputed matching/scoring metadata. */
export interface CompiledRule {
  path: string;
  methods: Set<string>;
  permissions?: string[];
  decision: DecisionMode;
  allowedServices?: string[];
  segments: Segment[];
  /** Per-segment specificity score: literal=2, single=1, deep=0. */
  scores: number[];
  literalCount: number;
  /** public:true -> no validation, always ALLOW. */
  isPublic: boolean;
}

export type AuthType = "USER" | "SERVICE" | "USER_AND_SERVICE";

export interface AuthorizationRequest {
  method: string;
  path: string;
  authType: AuthType;
  role?: string | null;
  serviceName?: string | null;
}

export type Decision = "ALLOW" | "DENY";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}
