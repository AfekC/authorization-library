/**
 * In-memory role -> permissions store. Immutable from the caller's perspective:
 * every update produces a fresh internal map that atomically replaces the active
 * reference (copy-on-replace). In-flight reads always see a complete map.
 */
export class PermissionCache {
  private active: ReadonlyMap<string, ReadonlySet<string>>;
  private _version: number;
  private _lastUpdatedAt: Date;
  private _writeLock: Promise<void> = Promise.resolve();

  constructor(initial?: Record<string, string[]>) {
    this.active = PermissionCache.build(initial ?? {});
    this._version = 0;
    this._lastUpdatedAt = new Date();
  }

  private async acquireLock(): Promise<() => void> {
    let release: () => void;
    const next = new Promise<void>((resolve) => { release = resolve; });
    const prev = this._writeLock;
    this._writeLock = next;
    await prev;
    return release!;
  }

  private static build(
    roles: Record<string, string[]>,
  ): ReadonlyMap<string, ReadonlySet<string>> {
    const map = new Map<string, ReadonlySet<string>>();
    for (const [role, perms] of Object.entries(roles)) {
      map.set(role, new Set(perms));
    }
    return map;
  }

  /** Empty set for an unknown role — no implicit grants. */
  permissionsForRole(role: string | null | undefined): ReadonlySet<string> {
    if (!role) return new Set();
    return this.active.get(role) ?? new Set();
  }

  version(): number {
    return this._version;
  }

  lastUpdatedAt(): Date {
    return this._lastUpdatedAt;
  }

  /**
   * Replace the whole map atomically (e.g. after a Role Service snapshot).
   * Bumps an internal generation counter for observability — the Role Service
   * no longer supplies a version.
   */
  async replaceAll(roles: Record<string, string[]>): Promise<void> {
    const release = await this.acquireLock();
    try {
      this.active = PermissionCache.build(roles);
      this._version += 1;
      this._lastUpdatedAt = new Date();
    } finally {
      release();
    }
  }

  /** Insert or fully replace one role (Kafka UPSERT_ROLE). */
  async upsertRole(role: string, permissions: string[]): Promise<void> {
    const release = await this.acquireLock();
    try {
      const next = new Map(this.active);
      next.set(role, new Set(permissions));
      this.active = next;
      this._version += 1;
      this._lastUpdatedAt = new Date();
    } finally {
      release();
    }
  }

  /** Remove one role (Kafka DELETE_ROLE). */
  async deleteRole(role: string): Promise<void> {
    const release = await this.acquireLock();
    try {
      const next = new Map(this.active);
      next.delete(role);
      this.active = next;
      this._version += 1;
      this._lastUpdatedAt = new Date();
    } finally {
      release();
    }
  }

  /** Serializable snapshot for disk persistence. */
  toSnapshot(): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    for (const [role, perms] of this.active) out[role] = [...perms];
    return out;
  }
}
