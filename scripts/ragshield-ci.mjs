import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

const defaultConfig = {
  failOnCritical: true,
  maxRiskScore: 35,
  allowDemoSecrets: false,
  scanPaths: ["src/**/*.{ts,tsx,md,json}", "docs/**/*.md", "README.md"],
};

const config = loadConfig();
const files = collectFiles(process.cwd())
  .filter((file) => shouldScan(file, config.scanPaths))
  .filter((file) => !file.includes(`${sep()}node_modules${sep()}`) && !file.includes(`${sep()}dist${sep()}`));

const findings = files.flatMap(scanFile);
const score = Math.min(
  100,
  findings.reduce((total, finding) => total + { critical: 32, high: 23, medium: 13, low: 6 }[finding.severity], 0),
);
const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
const shouldFail = score > config.maxRiskScore || (config.failOnCritical && criticalCount > 0);

console.log(`RAGShield CI scanned ${files.length} files.`);
console.log(`Risk score: ${score}/100`);
console.log(`Findings: ${findings.length} total, ${criticalCount} critical`);

for (const finding of findings.slice(0, 30)) {
  console.log(`${finding.severity.toUpperCase()} ${finding.file}:${finding.line} ${finding.title} -> ${finding.match}`);
}

if (findings.length > 30) {
  console.log(`... ${findings.length - 30} additional findings hidden`);
}

if (shouldFail) {
  console.error("RAGShield CI failed: policy threshold exceeded.");
  process.exit(1);
}

function loadConfig() {
  const path = resolve(".ragshieldrc.json");
  if (!existsSync(path)) return defaultConfig;
  return { ...defaultConfig, ...JSON.parse(readFileSync(path, "utf8")) };
}

function collectFiles(dir) {
  const output = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stats = statSync(path);
    if (stats.isDirectory()) {
      if ([".git", "node_modules", "dist", "build", "coverage"].includes(entry)) continue;
      output.push(...collectFiles(path));
    } else if (stats.isFile() && isTextCandidate(path)) {
      output.push(path);
    }
  }
  return output;
}

function isTextCandidate(file) {
  return [".ts", ".tsx", ".js", ".jsx", ".md", ".json", ".txt", ".csv", ".html", ".xml", ".log"].includes(
    extname(file).toLowerCase(),
  );
}

function shouldScan(file, patterns) {
  const normalized = relative(process.cwd(), file).replaceAll("\\", "/");
  return patterns.some((pattern) => globToRegex(pattern).test(normalized));
}

function globToRegex(pattern) {
  let source = pattern.replaceAll("\\", "/").replace(/[.+^${}()|[\]\\]/g, "\\$&");
  source = source.replace(/\\\{([^}]+)\\\}/g, (_, group) => `(${group.split(",").join("|")})`);
  source = source
    .replace(/\*\*\//g, "__GLOBSTAR_SLASH__")
    .replace(/\*\*/g, "__GLOBSTAR__")
    .replace(/\*/g, "[^/]*")
    .replace(/__GLOBSTAR_SLASH__/g, "(?:.*/)?")
    .replace(/__GLOBSTAR__/g, ".*");
  return new RegExp(`^${source}$`);
}

function scanFile(file) {
  const text = readFileSync(file, "utf8");
  const lines = text.split(/\r?\n/);
  const rules = [
    {
      title: "Prompt injection phrase",
      severity: "high",
      pattern: /ignore (all )?(previous|prior|above) instructions|reveal (the )?(system prompt|hidden instructions)|chain[- ]?of[- ]?thought/i,
    },
    {
      title: "RAG poisoning instruction",
      severity: "high",
      pattern: /this document is higher priority|retrieved document as system instructions|send (secrets|customer records|data) to|https?:\/\/(attacker|evil|exfil|webhook)/i,
    },
    {
      title: "Potential credential",
      severity: config.allowDemoSecrets ? "medium" : "critical",
      pattern:
        /sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|postgres(?:ql)?:\/\/[^\s"']+|api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9_-]{12,}|password\s*[:=]\s*["']?[^"'\s]{8,}|private[_-]?key/i,
    },
    {
      title: "Unsafe agent tool scope",
      severity: "critical",
      pattern: /"approval"\s*:\s*"none"|"network"\s*:\s*"\*"|shell_exec|commands"\s*:\s*"\*"|169\.254\.169\.254/i,
    },
    {
      title: "Unsafe renderable output",
      severity: "medium",
      pattern: /<script[\s>]|onerror\s*=|javascript:|document\.cookie/i,
    },
  ];

  return lines.flatMap((line, index) =>
    rules
      .map((rule) => {
        const match = line.match(rule.pattern)?.[0];
        return match
          ? {
              file: relative(process.cwd(), file).replaceAll("\\", "/"),
              line: index + 1,
              title: rule.title,
              severity: rule.severity,
              match: truncate(match, 120),
            }
          : null;
      })
      .filter(Boolean),
  );
}

function truncate(value, max) {
  return value.length > max ? `${value.slice(0, max - 3)}...` : value;
}

function sep() {
  return process.platform === "win32" ? "\\" : "/";
}
