// Downloads the blastradius binary for this platform from GitHub Releases.
//
// The binary is the product; this package exists so that `npx blastradius`
// works without a Go toolchain.
const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

const REPO = "cobrabm12/blastradius";
const VERSION = require("./package.json").version;

const PLATFORMS = {
  "linux-x64": "linux_amd64",
  "linux-arm64": "linux_arm64",
  "darwin-x64": "darwin_amd64",
  "darwin-arm64": "darwin_arm64",
  "win32-x64": "windows_amd64",
  "win32-arm64": "windows_arm64",
};

const key = `${process.platform}-${process.arch}`;
const target = PLATFORMS[key];
if (!target) {
  console.error(`blastradius: no prebuilt binary for ${key}.`);
  console.error("Install from source instead:");
  console.error(`  go install github.com/${REPO}/cmd/blastradius@latest`);
  process.exit(1);
}

const isWindows = process.platform === "win32";
const ext = isWindows ? "zip" : "tar.gz";
const url = `https://github.com/${REPO}/releases/download/v${VERSION}/blastradius_${VERSION}_${target}.${ext}`;

const binDir = path.join(__dirname, "bin");
fs.mkdirSync(binDir, { recursive: true });
const archive = path.join(binDir, `blastradius.${ext}`);

function download(from, to, redirects = 0) {
  if (redirects > 10) throw new Error("too many redirects");
  return new Promise((resolve, reject) => {
    https
      .get(from, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          resolve(download(res.headers.location, to, redirects + 1));
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode} for ${from}`));
          return;
        }
        const file = fs.createWriteStream(to);
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
        file.on("error", reject);
      })
      .on("error", reject);
  });
}

download(url, archive)
  .then(() => {
    if (isWindows) {
      execSync(`powershell -Command "Expand-Archive -Force '${archive}' '${binDir}'"`);
    } else {
      execSync(`tar -xzf "${archive}" -C "${binDir}"`);
      fs.chmodSync(path.join(binDir, "blastradius"), 0o755);
    }
    fs.unlinkSync(archive);
  })
  .catch((err) => {
    console.error(`blastradius: could not download the binary: ${err.message}`);
    console.error("Install from source instead:");
    console.error(`  go install github.com/${REPO}/cmd/blastradius@latest`);
    process.exit(1);
  });
