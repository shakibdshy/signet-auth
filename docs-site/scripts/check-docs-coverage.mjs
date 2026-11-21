// Guards the docs site against undocumented public API and stale references.
// Run with `npm run docs:check`; verify the guard logic with `--self-test`.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../..", import.meta.url).pathname;
const docsDir = join(root, "docs-site", "content", "docs");
const requiredPages = [
  "configuration.mdx",
  "http-api.mdx",
  "errors.mdx",
  "security.mdx",
  "storage.mdx",
  "tooling.mdx",
  "go-api.mdx",
  "status.mdx",
];

function read(relative) {
  return readFileSync(join(root, relative), "utf8");
}

function mdxFiles(dir) {
  return readdirSync(dir, { recursive: true })
    .filter((name) => typeof name === "string" && name.endsWith(".mdx"))
    .map((name) => readFileSync(join(dir, name), "utf8"))
    .join("\n");
}

function collectSymbols() {
  const client = read("client.go");
  const signet = read("signet.go");
  const errors = read("errors.go");
  const core = read("internal/core/core.go");
  const contract = read("internal/httpapi/contract.go");
  const names = new Set();

  for (const match of client.matchAll(/^func \(c \*Client\) ([A-Z]\w*)\(/gm)) names.add(match[1]);
  for (const match of signet.matchAll(/^type ([A-Z]\w*) =/gm)) names.add(match[1]);
  for (const match of signet.matchAll(/^\s*([A-Z]\w*)\s+=\s+core\./gm)) names.add(match[1]);
  if (/^const Version\b/m.test(signet)) names.add("Version");
  for (const match of errors.matchAll(/^\s*(Err[A-Z]\w*)\s+=/gm)) names.add(match[1]);

  // Config fields are declared between `type Config struct {` and its closing brace.
  const configStart = core.indexOf("type Config struct {");
  if (configStart >= 0) {
    const end = core.indexOf("\n}", configStart);
    for (const line of core.slice(configStart, end).split("\n")) {
      const match = line.match(/^\s*([A-Z]\w*)\s+/);
      if (match) names.add(match[1]);
    }
  }

  // Endpoint names are the `Name:` fields of ContractFor's endpoint table.
  for (const match of contract.matchAll(/\{Name: "([^"]+)"/g)) names.add(match[1]);
  return names;
}

function check(collected, docsText, pageExists = (page) => existsSync(join(docsDir, page))) {
  const problems = [];
  for (const name of [...collected.symbols].sort()) {
    if (!docsText.includes(name)) problems.push(`MISSING docs: ${name}`);
  }
  for (const name of [...new Set([...docsText.matchAll(/\b(Err[A-Z]\w*)\b/g)].map((m) => m[1]))].sort()) {
    if (!collected.errors.has(name)) problems.push(`STALE docs: ${name}`);
  }
  for (const page of collected.pages) {
    if (!pageExists(page)) problems.push(`MISSING page: ${page}`);
  }
  return problems;
}

function selfTest() {
  const collected = {
    symbols: new Set(["SignUp", "Config", "signup"]),
    errors: new Set(["ErrNotFound"]),
    pages: ["configuration.mdx"],
  };
  const docs = "Use SignUp and Config with ErrNotFound. Mention ErrNotReal too.";
  const problems = check(collected, docs, () => true);
  const expected = ["MISSING docs: signup", "STALE docs: ErrNotReal"];
  if (JSON.stringify(problems) !== JSON.stringify(expected)) {
    console.error("self-test FAILED", { problems, expected });
    process.exit(1);
  }
  console.log("docs coverage guard self-test OK");
}

if (process.argv.includes("--self-test")) {
  selfTest();
} else {
  const problems = check(
    { symbols: collectSymbols(), errors: new Set(read("errors.go").match(/\bErr[A-Z]\w*\b/g) || []), pages: requiredPages },
    mdxFiles(docsDir),
  );
  // The site builds its API reference from its own copy of the generated spec.
  // It must match the root artifact or newly added endpoints never render.
  const published = read("api/signet.openapi.json");
  const siteSpec = read("docs-site/openapi/signet.openapi.json");
  if (published !== siteSpec) {
    problems.push("STALE docs-site spec: run `npm run sync:spec` in docs-site");
  }
  if (problems.length) {
    console.error(problems.join("\n"));
    console.error(`\n${problems.length} documentation coverage problem(s).`);
    process.exit(1);
  }
  console.log("documentation coverage OK");
}
