#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..", "payloads");
const requiredCategories = [
  "command-injection",
  "fuzz",
  "graphql",
  "jwt",
  "nosqli",
  "path-traversal",
  "sqli",
  "ssrf",
  "xss",
];
const forbiddenPatterns = [
  [/document\.cookie/i, "browser cookie access"],
  [/169\.254\.169\.254/, "cloud metadata address"],
  [/\/etc\/passwd/i, "real operating-system file"],
  [/\b(?:whoami|hostname|xp_cmdshell)\b/i, "system discovery or shell execution"],
  [/\$\(\s*id\s*\)|`\s*id\s*`/, "command substitution"],
  [/\b(?:DROP|DELETE|UPDATE|INSERT)\b\s+/i, "data-changing SQL"],
  [/https?:\/\/(?![^\s/]*\.(?:invalid|example)(?:[/:]|$))/i, "non-reserved network target"],
];

const errors = [];

function fail(file, message) {
  errors.push(`${path.relative(process.cwd(), file)}: ${message}`);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    fail(file, `invalid JSON (${error.message})`);
    return null;
  }
}

for (const category of requiredCategories) {
  const directory = path.join(root, category);
  const readme = path.join(directory, "README.md");
  const metadataFile = path.join(directory, "metadata.json");

  if (!fs.existsSync(directory)) {
    fail(directory, "required category is missing");
    continue;
  }
  if (!fs.existsSync(readme)) fail(readme, "README is missing");
  if (!fs.existsSync(metadataFile)) {
    fail(metadataFile, "metadata index is missing");
    continue;
  }

  const metadata = readJson(metadataFile);
  if (!metadata || !Array.isArray(metadata.payloads)) continue;

  const files = fs.readdirSync(directory).filter((name) => name.endsWith(".payload"));
  const indexed = new Set(metadata.payloads.map((entry) => entry.filename));
  for (const filename of files) {
    if (!indexed.has(filename)) fail(path.join(directory, filename), "not indexed by metadata.json");
  }

  let categoryCount = 0;
  for (const entry of metadata.payloads) {
    const file = path.join(directory, entry.filename);
    if (!fs.existsSync(file)) {
      fail(file, "indexed payload file is missing");
      continue;
    }

    const text = fs.readFileSync(file, "utf8");
    if (!text.startsWith("---\n")) fail(file, "YAML front matter must start on line 1");
    const closing = text.indexOf("\n---\n", 4);
    if (closing === -1) {
      fail(file, "YAML front matter has no closing delimiter");
      continue;
    }

    const body = text.slice(closing + 5);
    const examples = body
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"));
    categoryCount += examples.length;

    if (entry.example_count !== examples.length) {
      fail(file, `metadata declares ${entry.example_count} examples but file contains ${examples.length}`);
    }
    for (const [pattern, reason] of forbiddenPatterns) {
      if (pattern.test(body)) fail(file, `contains forbidden ${reason}`);
    }
  }

  if (categoryCount < 11) fail(directory, `contains only ${categoryCount} examples; at least 11 are required`);
  if (metadata.example_count !== categoryCount) {
    fail(metadataFile, `declares ${metadata.example_count} examples but category contains ${categoryCount}`);
  }
}

if (errors.length) {
  console.error(`Payload validation failed with ${errors.length} error(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Validated ${requiredCategories.length} categories; each contains at least 11 safe examples.`);
