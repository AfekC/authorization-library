import * as fs from "fs";
import { PermissionCache } from "../permission-cache/cache";

export interface DiskSnapshot {
  timestamp: string;
  roles: Record<string, string[]>;
}

/** Persists / loads the fallback cache file (authorization-cache.json). */
export class DiskCache {
  constructor(private readonly path: string) {}

  /**
   * Persist the cache snapshot to disk. Returns null on success, or the Error
   * on failure (EACCES, ENOSPC, missing directory, etc.). Never throws — callers
   * must log + metric on a non-null return and keep serving from the in-memory cache.
   */
  write(cache: PermissionCache): Error | null {
    const snapshot: DiskSnapshot = {
      timestamp: new Date().toISOString(),
      roles: cache.toSnapshot(),
    };
    try {
      fs.writeFileSync(this.path, JSON.stringify(snapshot, null, 2), "utf8");
      return null;
    } catch (e) {
      return e instanceof Error ? e : new Error(String(e));
    }
  }

  exists(): boolean {
    return fs.existsSync(this.path);
  }

  /** Read the seed snapshot, or null if absent/unreadable. */
  read(): DiskSnapshot | null {
    if (!this.exists()) return null;
    try {
      const parsed = JSON.parse(
        fs.readFileSync(this.path, "utf8"),
      ) as DiskSnapshot;
      // Guard must explicitly reject null and arrays:
      // typeof null === "object" in JS, so a plain `typeof x !== "object"` check
      // passes for null, causing Object.keys(seed.roles) to throw TypeError at
      // startup (C1). Arrays are also typeof "object" but not a valid role map.
      if (
        !parsed ||
        parsed.roles === null ||
        typeof parsed.roles !== "object" ||
        Array.isArray(parsed.roles)
      ) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }
}
