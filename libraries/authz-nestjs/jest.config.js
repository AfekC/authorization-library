/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  // Buffers console per-test and replays it only when a test fails (quiet on
  // success, full logs on failure). See test/buffered-console.env.cjs.
  testEnvironment: "<rootDir>/test/buffered-console.env.cjs",
  rootDir: ".",
  testMatch: ["**/test/**/*.spec.ts", "**/src/**/*.spec.ts"],
  moduleFileExtensions: ["ts", "js", "json"],
};
