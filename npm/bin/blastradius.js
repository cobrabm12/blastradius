#!/usr/bin/env node
// Thin launcher: runs the platform binary fetched by install.js.
const path = require("path");
const { spawnSync } = require("child_process");

const binary = path.join(
  __dirname,
  process.platform === "win32" ? "blastradius.exe" : "blastradius"
);
const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
process.exit(result.status === null ? 1 : result.status);
