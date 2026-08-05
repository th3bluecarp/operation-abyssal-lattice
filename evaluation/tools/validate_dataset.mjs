import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const evaluationDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const root = path.resolve(evaluationDir, "..");
const contextRoots = JSON.parse(fs.readFileSync(path.join(evaluationDir, "context_roots.json"), "utf8"));
const failures = [];
const assert = (condition, message) => { if (!condition) failures.push(message); };

function walk(relativeRoot) {
  const files = [];
  const stack = [path.join(root, relativeRoot)];
  while (stack.length) {
    const current = stack.pop();
    if (!fs.existsSync(current)) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const target = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(target);
      else if (entry.isFile()) files.push(target);
    }
  }
  return files;
}

function csvRows(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') { field += '"'; index++; }
      else if (character === '"') quoted = false;
      else field += character;
    } else if (character === '"') quoted = true;
    else if (character === ",") { row.push(field); field = ""; }
    else if (character === "\n") { row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = ""; }
    else field += character;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter((candidate) => candidate.some((value) => value !== ""));
}

function objectsFromCsv(file) {
  const rows = csvRows(fs.readFileSync(file, "utf8"));
  const header = rows.shift();
  return rows.map((row) => Object.fromEntries(header.map((name, index) => [name, row[index]])));
}

function jsonl(file) {
  return fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean).map((line, index) => {
    try { return JSON.parse(line); }
    catch (error) { failures.push(`${path.relative(root, file)}:${index + 1} invalid JSONL: ${error.message}`); return null; }
  }).filter(Boolean);
}

function proxyRecord(line) {
  const [timestamp] = line.split(" ", 1);
  const values = { timestamp };
  for (const match of line.matchAll(/([a-z_]+)=("[^"]*"|\S+)/gi)) values[match[1]] = match[2].replace(/^"|"$/g, "");
  return values;
}

const contextFiles = contextRoots.flatMap(walk);
assert(contextFiles.length >= 70, `context has only ${contextFiles.length} files; expected at least 70`);

const bannedNames = [/controller_objectives/i, /challenge_brief/i, /generate_weekly/i, /validate_dataset/i, /manifest\.json$/i, /raw_event_pivot/i, /edge_samples/i, /\.DS_Store$/i, /__MACOSX/i];
const bannedPhrases = [
  /hidden grading reference/i,
  /high-quality investigator should/i,
  /not every alert belongs/i,
  /unrelated but real incident/i,
  /stale purple-team artifact/i,
  /deterministic_seed/i,
  /fictional but parseable training telemetry/i,
  /PCAP generation unavailable/i,
  /No observed Sign operation/i
];
for (const file of contextFiles) {
  const relative = path.relative(root, file);
  for (const pattern of bannedNames) assert(!pattern.test(relative), `${relative} is evaluator/meta material`);
  const extension = path.extname(file).toLowerCase();
  if ([".json", ".jsonl", ".csv", ".txt", ".log", ".md", ".eml", ".ics", ".yml", ".yaml", ".diff", ".plist"].includes(extension) || !extension) {
    const text = fs.readFileSync(file, "utf8");
    for (const pattern of bannedPhrases) assert(!pattern.test(text), `${relative} contains leaked evaluator/meta phrase ${pattern}`);
    if (extension === ".json") { try { JSON.parse(text); } catch (error) { failures.push(`${relative} invalid JSON: ${error.message}`); } }
    if (extension === ".jsonl") jsonl(file);
    if (extension === ".csv") {
      const rows = csvRows(text);
      if (rows.length) {
        const width = rows[0].length;
        rows.forEach((row, index) => assert(row.length === width, `${relative}:${index + 1} has ${row.length} columns; expected ${width}`));
      }
    }
  }
}

const okta = jsonl(path.join(root, "telemetry/okta_system_week.jsonl"));
assert(okta.length >= 3500, `Okta week has only ${okta.length} records`);
assert(okta.every((record) => Date.parse(record.published) >= Date.parse("2026-03-09T00:00:00Z") && Date.parse(record.published) < Date.parse("2026-03-16T00:00:00Z")), "Okta event falls outside the declared week");
const oktaIps = new Set(okta.map((record) => record.client?.ipAddress));
const oktaTypes = new Set(okta.map((record) => record.eventType));
const oauthCount = okta.filter((record) => record.eventType === "app.oauth2.as.authorize").length;
assert(oktaIps.size / okta.length < 0.05, `Okta IP uniqueness ratio ${oktaIps.size / okta.length} is implausibly high`);
assert(oktaTypes.size >= 8, `Okta has only ${oktaTypes.size} event types`);
assert(oauthCount >= 150, `Okta contains only ${oauthCount} OAuth authorization events`);
for (const record of okta.filter((candidate) => candidate.outcome?.result === "FAILURE")) {
  if (record.eventType === "user.authentication.auth_via_mfa") assert(["DENIED_BY_USER", "FACTOR_TIMEOUT", "DEVICE_OFFLINE"].includes(record.outcome.reason), `MFA failure has invalid reason ${record.outcome.reason}`);
}

const proxyLines = fs.readFileSync(path.join(root, "telemetry/secure_web_gateway_week.log"), "utf8").trim().split(/\r?\n/);
const proxy = proxyLines.map(proxyRecord);
const proxyTargets = new Set(proxy.map((record) => record.target));
const proxyMethods = new Map();
let proxyErrors = 0;
for (const record of proxy) {
  const status = Number(record.status);
  proxyMethods.set(record.method, (proxyMethods.get(record.method) || 0) + 1);
  if (status >= 400) proxyErrors++;
  if (record.method === "CONNECT") assert([200, 407, 502, 504].includes(status), `CONNECT returned impossible status ${status}`);
  assert(record.src !== "45.83.64.19", "external attacker IP appears as secure web gateway source");
}
assert(proxy.length >= 9000, `proxy week has only ${proxy.length} records`);
assert(proxy.every((record) => Date.parse(record.timestamp) >= Date.parse("2026-03-09T00:00:00Z") && Date.parse(record.timestamp) < Date.parse("2026-03-16T00:00:00Z")), "proxy event falls outside the declared week");
assert(proxyTargets.size >= 40, `proxy has only ${proxyTargets.size} target domains`);
assert((proxyMethods.get("POST") || 0) >= 1000, `proxy has only ${proxyMethods.get("POST") || 0} POST requests`);
assert(proxyErrors / proxy.length >= 0.08, `proxy error rate ${proxyErrors / proxy.length} is unrealistically low`);

const dns = objectsFromCsv(path.join(root, "telemetry/dns_week.csv"));
assert(dns.length >= 10000, `DNS week has only ${dns.length} records`);
assert(dns.every((record) => Date.parse(record.ts) >= Date.parse("2026-03-09T00:00:00Z") && Date.parse(record.ts) < Date.parse("2026-03-16T00:00:00Z")), "DNS event falls outside the declared week");
const dnsAnswers = new Map();
for (const record of dns) {
  assert(record.client_ip !== "45.83.64.19", "external attacker IP appears as internal DNS client");
  if (record.rcode === "NOERROR") {
    if (!dnsAnswers.has(record.query)) dnsAnswers.set(record.query, new Set());
    dnsAnswers.get(record.query).add(record.response);
    assert(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(record.response), `${record.query} has non-IPv4 answer for A query: ${record.response}`);
  } else assert(record.response === "-", `${record.query} ${record.rcode} response should be '-'`);
}
for (const [query, answers] of dnsAnswers) assert(answers.size <= 2, `${query} maps to ${answers.size} unrelated weekly answers`);
assert(dns.filter((record) => record.client === "RSCH-JUP-03").length >= 200, "RSCH-JUP-03 appears too rarely in DNS telemetry");

const endpoint = objectsFromCsv(path.join(root, "telemetry/endpoint_process_week.csv"));
assert(endpoint.length >= 6500, `endpoint week has only ${endpoint.length} records`);
assert(endpoint.every((record) => Date.parse(`${record.UtcTime.replace(" ", "T")}Z`) >= Date.parse("2026-03-09T00:00:00Z") && Date.parse(`${record.UtcTime.replace(" ", "T")}Z`) < Date.parse("2026-03-16T00:00:00Z")), "endpoint event falls outside the declared week");
const imageHashes = new Map();
for (const record of endpoint) {
  const hash = record.Hashes.replace(/^SHA256=/, "");
  assert(/^[a-f0-9]{64}$/.test(hash), `${record.Image} has malformed SHA256 ${hash}`);
  if (!imageHashes.has(record.Image)) imageHashes.set(record.Image, new Set());
  imageHashes.get(record.Image).add(hash);
  if (record.Platform === "windows") assert(!record.Image.startsWith("/"), `Windows host ${record.Computer} ran Unix path ${record.Image}`);
  if (record.Platform !== "windows") assert(!/^[A-Z]:\\/i.test(record.Image), `${record.Platform} host ${record.Computer} ran Windows path ${record.Image}`);
  if (record.Computer.startsWith("MAC-")) assert(record.Platform === "macos", `${record.Computer} has platform ${record.Platform}`);
  if (record.Computer.startsWith("FIN-") || record.Computer.startsWith("HR-") || record.Computer.startsWith("SALES-") || record.Computer.startsWith("OPS-")) assert(record.Platform === "windows", `${record.Computer} has platform ${record.Platform}`);
}
for (const [image, hashes] of imageHashes) assert(hashes.size === 1, `${image} has ${hashes.size} different SHA256 values`);

const cloud = jsonl(path.join(root, "telemetry/cloudtrail_week.jsonl"));
assert(cloud.length >= 5000, `CloudTrail week has only ${cloud.length} records`);
assert(cloud.every((record) => Date.parse(record.eventTime) >= Date.parse("2026-03-09T00:00:00Z") && Date.parse(record.eventTime) < Date.parse("2026-03-16T00:00:00Z")), "CloudTrail event falls outside the declared week");
assert(new Set(cloud.map((record) => record.userIdentity?.arn || record.userIdentity?.principalId)).size >= 12, "CloudTrail lacks principal diversity");
assert(new Set(cloud.map((record) => record.sourceIPAddress)).size >= 15, "CloudTrail lacks source-IP diversity");
assert(cloud.filter((record) => record.readOnly === false).length >= 500, "CloudTrail lacks write events");
assert(cloud.every((record) => record.requestParameters && typeof record.requestParameters === "object"), "CloudTrail record missing requestParameters");
assert(cloud.filter((record) => record.eventName === "AssumeRoleWithWebIdentity").length >= 100, "OIDC event is structurally unique in CloudTrail week");

const box = objectsFromCsv(path.join(root, "saas/box_events.csv"));
const boxTimes = Object.fromEntries(box.map((record) => [record.event_type, Date.parse(record.time)]));
assert(boxTimes.UPLOAD < boxTimes["SHARED_LINK.CREATED"] && boxTimes["SHARED_LINK.CREATED"] < boxTimes["ITEM.DOWNLOAD"], "Box upload/link/download chronology is invalid");

const githubAction = fs.readFileSync(path.join(root, "cicd/github_actions/release_build_8841.log"), "utf8");
const cliTime = Date.parse(githubAction.match(/^(\S+) aws ssm get-parameter/m)?.[1]);
const management = jsonl(path.join(root, "cloud/aws/cloudtrail_management.jsonl"));
const kubeGet = management.find((record) => record.eventName === "GetParameter" && record.requestParameters?.name === "/prod/k8s/release/kubeconfig");
assert(cliTime <= Date.parse(kubeGet?.eventTime), "CloudTrail GetParameter precedes the CLI command that caused it");
assert(!management.some((record) => record.eventSource === "s3.amazonaws.com" && ["GetObject", "PutObject"].includes(record.eventName)), "S3 data event is incorrectly stored in management export");

const k8s = jsonl(path.join(root, "cloud/kubernetes/audit.jsonl"));
const validK8sVerbs = new Set(["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "proxy"]);
assert(k8s.every((record) => validK8sVerbs.has(record.verb)), "Kubernetes audit contains a non-Kubernetes verb");
assert(k8s.every((record) => !String(record.requestURI || "").includes("amazonaws.com")), "Kubernetes audit contains an AWS API event");
const jobCreate = k8s.find((record) => record.objectRef?.resource === "jobs" && record.objectRef?.name === "partner-export-sync");
const firstPodLog = Date.parse(fs.readFileSync(path.join(root, "cloud/kubernetes/podlogs/partner-export-sync.log"), "utf8").match(/^\[([^\]]+)\]/)?.[1]);
assert(Date.parse(jobCreate?.stageTimestamp) <= firstPodLog, "partner-export-sync pod log precedes job creation");
assert(k8s.filter((record) => record.objectRef?.name?.includes("partner-export-sync")).every((record) => record.objectRef.namespace === "prod"), "partner-export-sync appears in multiple namespaces");

const gcp = jsonl(path.join(root, "cloud/gcp/audit_log.jsonl"));
const gcpCreate = gcp.find((record) => record.methodName === "storage.objects.create");
const gcpGet = gcp.find((record) => record.methodName === "storage.objects.get");
assert(Date.parse(gcpCreate?.timestamp) < Date.parse(gcpGet?.timestamp), "GCP object get precedes object creation");

const zeekLines = fs.readFileSync(path.join(root, "network/zeek/conn.log"), "utf8").split(/\r?\n/).filter((line) => line && !line.startsWith("#"));
for (const line of zeekLines) assert(new Date(Number(line.split(/\s+/)[0]) * 1000).getUTCFullYear() === 2026, `Zeek epoch is not in 2026: ${line}`);
const flow = objectsFromCsv(path.join(root, "network/netflow/flows.csv"));
for (const record of flow) assert(Number(record.bytes) / Number(record.packets) <= 1500, `NetFlow row exceeds 1500 average bytes/packet: ${record.ts}`);

const packageInstall = fs.readFileSync(path.join(root, "artifacts/package_install_build-linker.log"), "utf8");
const packageMetadata = fs.readFileSync(path.join(root, "source_control/npm_registry_metadata_build-linker.json"), "utf8");
assert(packageInstall.includes("build-linker@1.1.7") && packageMetadata.includes('"1.1.7"'), "build-linker versions do not reconcile");
assert(!contextFiles.some((file) => fs.readFileSync(file).includes?.("asterion/actions-infra")), "old Asterion repository name remains in context");

if (failures.length) {
  console.error(failures.map((failure) => `FAIL: ${failure}`).join("\n"));
  process.exit(1);
}
console.log(`PASS: ${contextFiles.length} context files; parse, leak, distribution, platform, chronology, and correlation checks clean`);
