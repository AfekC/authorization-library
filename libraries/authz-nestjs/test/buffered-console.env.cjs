/**
 * Custom Jest environment: keep the console quiet on success, loud on failure.
 *
 * The authz library logs audit lines (and fail-open warnings) on every decision.
 * During passing tests those flood Jest's "● Console" output even though nothing
 * is wrong. This environment buffers each test's console output and replays it
 * ONLY when that test fails — so a green run is silent and a red run still shows
 * everything the failing test logged.
 */
const { TestEnvironment } = require("jest-environment-node");

const METHODS = ["log", "info", "debug", "warn", "error", "trace"];

class BufferedConsoleEnvironment extends TestEnvironment {
  constructor(config, context) {
    super(config, context);
    // Array while a test is running, null otherwise (logs outside a test pass
    // straight through — e.g. beforeAll setup).
    this.logBuffer = null;
  }

  async setup() {
    await super.setup();
    const console = this.global.console;
    for (const method of METHODS) {
      if (typeof console[method] !== "function") continue;
      const original = console[method].bind(console);
      console[method] = (...args) => {
        if (this.logBuffer) {
          this.logBuffer.push([original, args]);
        } else {
          original(...args);
        }
      };
    }
  }

  handleTestEvent(event) {
    if (event.name === "test_start") {
      this.logBuffer = [];
    } else if (event.name === "test_done") {
      const failed = event.test && event.test.errors && event.test.errors.length > 0;
      if (failed && this.logBuffer) {
        for (const [emit, args] of this.logBuffer) emit(...args);
      }
      this.logBuffer = null;
    }
  }
}

module.exports = BufferedConsoleEnvironment;
