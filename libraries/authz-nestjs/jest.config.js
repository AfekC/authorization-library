/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  extensionsToTreatAsEsm: [".ts"],
  preset: "ts-jest/presets/default-esm",
  // Buffers console per-test and replays it only when a test fails (quiet on
  // success, full logs on failure). See test/buffered-console.env.cjs.
  testEnvironment: "<rootDir>/test/buffered-console.env.cjs",
  rootDir: ".",
  testMatch: ["**/test/**/*.spec.ts", "**/src/**/*.spec.ts"],
  moduleFileExtensions: ["ts", "js", "json"],
  transform: {
    "^.+\\.ts$": ["ts-jest", {
      useESM: true,
      tsconfig: "./tsconfig.json"
    }]
  },
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1"
  }
};
