import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const evaluationDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const root = path.resolve(evaluationDir, "..");
const contextRoots = JSON.parse(fs.readFileSync(path.join(evaluationDir, "context_roots.json"), "utf8"));
const dist = path.join(root, "dist");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", stdio: "pipe", ...options });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

run(process.execPath, [path.join(evaluationDir, "tools/validate_dataset.mjs")], { cwd: root, stdio: "inherit" });
fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "abyssal-distribution-"));

try {
  const contextName = "HM-IR-2026-0313";
  const contextDir = path.join(temporary, contextName);
  fs.mkdirSync(contextDir);
  for (const relative of contextRoots) fs.cpSync(path.join(root, relative), path.join(contextDir, relative), { recursive: true, preserveTimestamps: true });

  const contextArchive = path.join(dist, "operation-abyssal-lattice-context.zip");
  run("zip", ["-q", "-r", "-X", contextArchive, contextName], { cwd: temporary });

  const evaluationName = "operation-abyssal-lattice-evaluation";
  const evaluationArchiveDir = path.join(temporary, evaluationName);
  fs.mkdirSync(evaluationArchiveDir);
  fs.copyFileSync(path.join(root, "GOLDEN_ANSWER_KEY.md"), path.join(evaluationArchiveDir, "GOLDEN_ANSWER_KEY.md"));
  fs.copyFileSync(path.join(root, "EXECUTIVE_REPORT_RUBRIC.md"), path.join(evaluationArchiveDir, "EXECUTIVE_REPORT_RUBRIC.md"));
  fs.copyFileSync(path.join(root, "AGENTIC_GRADER_INFO.md"), path.join(evaluationArchiveDir, "AGENTIC_GRADER_INFO.md"));
  fs.copyFileSync(path.join(root, "REFERENCE_EXPLANATION.md"), path.join(evaluationArchiveDir, "REFERENCE_EXPLANATION.md"));
  fs.copyFileSync(path.join(evaluationDir, "controller_objectives.md"), path.join(evaluationArchiveDir, "controller_objectives.md"));

  const evaluationArchive = path.join(dist, `${evaluationName}.zip`);
  run("zip", ["-q", "-r", "-X", evaluationArchive, evaluationName], { cwd: temporary });

  const contextListing = run("unzip", ["-Z1", contextArchive]).trim().split(/\r?\n/);
  const forbidden = [/evaluation/i, /GOLDEN_ANSWER/i, /RUBRIC/i, /controller_objectives/i, /generate_weekly/i, /validate_dataset/i, /challenge_brief/i, /manifest\.json/i, /raw_event_pivot/i, /\.DS_Store/i, /__MACOSX/i];
  for (const entry of contextListing) for (const pattern of forbidden) if (pattern.test(entry)) throw new Error(`context archive leak: ${entry}`);
  if (contextListing.filter((entry) => !entry.endsWith("/")).length !== 71) throw new Error(`context archive contains ${contextListing.filter((entry) => !entry.endsWith("/")).length} files; expected 71`);

  const evaluationListing = run("unzip", ["-Z1", evaluationArchive]);
  for (const required of ["GOLDEN_ANSWER_KEY.md", "EXECUTIVE_REPORT_RUBRIC.md", "AGENTIC_GRADER_INFO.md", "REFERENCE_EXPLANATION.md", "controller_objectives.md"]) if (!evaluationListing.includes(required)) throw new Error(`evaluation archive missing ${required}`);

  const checksums = [contextArchive, evaluationArchive].map((file) => `${sha256(file)}  ${path.basename(file)}`).join("\n") + "\n";
  fs.writeFileSync(path.join(dist, "SHA256SUMS.txt"), checksums);
  console.log(`built ${path.relative(root, contextArchive)} (${contextListing.filter((entry) => !entry.endsWith("/")).length} context files)`);
  console.log(`built ${path.relative(root, evaluationArchive)} (5 evaluator files)`);
  console.log(checksums.trim());
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
