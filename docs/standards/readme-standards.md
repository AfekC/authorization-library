# README Standards & Best Practices

Standards for README files in this monorepo. The goal: a reader lands on any
README and, within seconds, knows **what this is, who it's for, and how to start**
— then finds accurate, copy-pasteable detail without wading through prose.

These are general documentation guidelines; apply them to any README in the repo.

---

## Part 1 — Universal principles (every README)

- **Audience-first.** The first one or two lines state *what the thing is* and
  *who it's for*. No history, no preamble.
- **Smallest working example early.** Show the minimal copy-pasteable snippet or
  command that produces a result before any reference material.
- **Progressive disclosure.** Required before optional; common before advanced;
  concrete before edge cases.
- **One canonical source.** A fact (a config table, a command, a property's
  default) lives in exactly one place. Everywhere else links to it. Duplicated
  tables drift and rot — link instead of copy.
- **Accuracy over completeness.** Every command, property name, path, and default
  must be real and current — verify against the code, not memory. A missing
  detail is better than a wrong one. When behavior changes, update the README in
  the same change.
- **Skimmable.** Use headings, tables for structured data (args/config), and
  fenced code blocks tagged with a language. Avoid walls of text.
- **Link, don't orphan.** Parent READMEs link down to child READMEs and vice
  versa. Use repo-relative links and clickable `path:line` references. No links
  to nonexistent anchors.
- **Secrets are never literals.** Never show a real secret; mark secret-valued
  config and note that it should be injected from a secret store, not committed.

## Part 2 — README tiers & required sections

Every README belongs to one tier. The tier determines its required sections (in
this order). Add optional sections only when they carry their weight.

### Root / monorepo README

The entry point. Optimized for orientation, not depth.

1. **Title + one-line purpose** — what the project is.
2. **Layout** — a short directory map.
3. **Getting Started** — route readers to the sub-project(s) they need; do not
   inline per-library detail here, link to it.
4. **Capabilities** — what it does, at a glance.
5. **Testing / running** — how to build, test, and run end-to-end.
6. **Documentation** — links to deeper design docs and standards.

### Library / package README (consumed by others)

The contract for adopters. Optimized for "how do I use this correctly."

1. **Title + one-line purpose.**
2. **Install / Add dependency.**
3. **Quick start** — the smallest working integration, copy-pasteable.
4. **Getting Started** — numbered, end-to-end steps. **Required arguments first
   (described inline)**, then optional settings **inline in the same flow** — not
   exiled to a section the reader has to go hunting for.
5. **Configuration reference** — the full argument list as a table (see Part 3).
6. **Extension points / public API** — SPI interfaces, exported surface.
7. **Testing** and **Build from source** (contributor concerns) come last.

> Lead with the consumer path (install → quick start → getting started).
> "Build from source / contribute" is a *contributor* concern — put it near the
> end, not at the top.

### Demo / example README

Optimized for "show me it working."

1. **Title + what it demonstrates** — and the framing (e.g. "simplest possible").
2. **The entire integration** — numbered steps, linking to the actual files.
3. **Run** — the exact command(s).
4. **Link** back to the library it exercises and to the e2e suite.

### Reference / contract README (spec)

Optimized for precision.

1. **Title + what it defines.**
2. **The shape / schema** — annotated.
3. **Where it's consumed.**

## Part 3 — Configuration documentation conventions

Configuration is where READMEs most often go wrong. Rules:

- **Use a table**, one row per argument, with these columns:
  `Name | Required | Type / Default | Description`. (Drop the column that doesn't
  apply — e.g. a "Required" table needs no default; an "optional" table always
  shows the default.)
- **Required arguments first**, optional second. Within optional, group related
  settings (e.g. all Kafka topics together).
- **Names must match the code's binding exactly** — verify against the
  properties/options class. (e.g. Spring relaxed binding: `authz.role-service-url`,
  *not* a nested `role-service.url`; the resource location is `authz.config-location`.)
- **Break out nested/sub-fields** (e.g. `serviceToken.tokenUrl`) rather than
  hiding them behind one opaque row.
- **State defaults** for every optional setting, and mark security-sensitive ones.
- Keep examples **minimal and real** — every value should be something a reader
  could plausibly use.

## Part 4 — Anti-patterns (do not do these)

- **Duplicated config tables** in two sections — they drift. One source, link.
- **Stale commands or property names** that no longer match the code.
- **A wall of prose with no runnable example.**
- **Required configuration documented *after* optional**, or optional config
  pushed into a remote section the Getting Started only references.
- **"Build from source in Docker" as the first thing a consumer sees.**
- **Broken anchors / links to files that moved.**

## Part 5 — Conformance checklist

Before merging a README change, confirm:

- [ ] First line says what it is and who it's for.
- [ ] A minimal working example/command appears early.
- [ ] Required config is documented before optional, both reachable in one place.
- [ ] Every command, path, property name, and default was verified against code.
- [ ] No duplicated tables; shared facts are linked, not copied.
- [ ] Secret-valued settings are flagged and never shown as literals.
- [ ] Internal links and anchors resolve.
- [ ] Sections follow this tier's required order.
