# Small-Project SIEM Schema vs Professional Schemas — Benchmark

## Summary

**Verdict: the proposed `events` + enriched `alerts` design is structurally sound and ~70% of the way to professional-grade for its scale — it already has the right *concepts* (outcome, severity, raw, host, MITRE, alert lifecycle status). Its gaps are almost all cheap discipline, not architecture:** (1) free-text severity instead of a numeric scale, (2) one overloaded `event_type` instead of category / type-or-class / action separation, (3) a single local-text `timestamp` instead of ISO-8601 UTC event time + a separate ingestion time, (4) `alert_type` as the only rule identity instead of stable `rule_id` + `rule_name`, (5) alerts carrying only `src_ip` (no destination, no target user, no link to the evidence event), and (6) no globally unique event id beyond the SQLite rowid. Fix those six in the column definitions below and the schema reads as ECS/OCSF/Wazuh/CIM-literate without importing any of their machinery.

**Naming verdict (the question that causes most bikeshedding): do NOT rename SQLite columns to ECS dot-notation.** ECS `source.ip`, Splunk CIM `src`, OCSF `src_endpoint.ip`, Wazuh `data.srcip` and Zeek `id.orig_h` are five different names for the same fact — the professional lesson is *one documented name per fact, plus a published mapping*, not any one spelling. Keep flat `snake_case` (`src_ip` is in fact exactly Splunk CIM Network_Traffic spelling), and ship an export/mapping view that emits ECS/OCSF names. See §3.3.

Confidence: high on ECS, OCSF, Splunk CIM, Zeek, Wazuh rule levels and alert JSON — all from official documentation opened live 2026-11-23 (see Sources). One correction to the mission brief: current Wazuh docs give `rule.level` **0–16**, not 0–15 (16 is reserved for custom rules; no default rule uses it).

---

## Findings

### 1. Field-by-field comparison

#### 1.0 Master crosswalk — project field → professional equivalents

| Project (existing + proposed) | ECS | OCSF (1.9) | Wazuh (`wazuh-alerts-*`) | Splunk CIM | Zeek `conn.log` |
|---|---|---|---|---|---|
| `timestamp` TEXT | `@timestamp` (date, required) + `event.ingested` | `time` (epoch ms) + `metadata` / ingestion concepts | `timestamp` → indexed as `@timestamp` | `_time` | `ts` (epoch float) |
| `src_ip` | `source.ip` (ip type) | `src_endpoint.ip` | `data.srcip` | Auth: `src` (alias of `src_ip`); Net_Traffic: `src_ip` **exact match** | `id.orig_h` |
| `dst_ip` (packets only) | `destination.ip` | `dst_endpoint.ip` | `data.dstip` | `dest_ip`; generic `dest` | `id.resp_h` |
| `src_port` / `dst_port` | `source.port` / `destination.port` (long) | `src_endpoint.port` / `dst_endpoint.port` | `data.srcport` | `src_port` / `dest_port` (number) **exact match** | `id.orig_p` / `id.resp_p` |
| `user_name` / `username` | `user.name` (keyword); also `user.id` | `user.name` (in `actor`/`user` object) | `data.srcuser` (+ `data.dstuser` for target) | `user`; priv-esc: `src_user` = actor, `user` = target | — |
| `host` (proposed, events) | `host.name` + `host.id` | `device.hostname` / `host` object | `agent.name` + `agent.id`, `manager.name` | `host`; reporting device = `dvc` | — (sensor not in conn row) |
| `event_source` (auth/system/host) | `event.module` + `event.dataset` + `event.provider` | `metadata.product` + `metadata.log_source` | `decoder.name`, `location` | `sourcetype` / `source` + `app` | log path (`conn`, `dns`…) |
| `event_type` (login_success…) | Split: `event.category` + `event.type` + `event.action` | Split: `category_uid` + `class_uid` + `activity_id` | `rule.groups[]` + decoder | dataset + `tag`/`eventtype` (e.g. `tag=authentication`) | — |
| `outcome` (success/failure) | `event.outcome`: `success\|failure\|unknown` | `status_id`: 1 Success / 2 Failure (+ `status` string) | implicit in rule/groups (`authentication_failed`) | Auth `action`: `success\|failure\|pending\|error` ⚠️ name collision — see §1.4 | `conn_state` is richer (SF/S0/REJ…) |
| `severity` TEXT info/low/med/high | `event.severity` (**long, numeric**, source-defined) | `severity_id` int + `severity` string sibling | `rule.level` int **0–16** | `severity`: `critical\|high\|medium\|low\|informational\|unknown` | — |
| `message` | `message` | `message` (concise summary, *not* raw) | `rule.description` (for alerts) | `signature` (human-readable name) | — |
| `raw` (proposed) | `event.original` (keyword, unindexed) | `raw_data` | `full_log` | `_raw` | — |
| `alert_type` | `rule.name` / `rule.id` (alert: `event.kind=alert`) | Detection Finding: `finding_info.title` / `finding_info.uid`, `type_uid` | `rule.id` + `rule.description` + `rule.groups[]` | `signature` + `signature_id` | `notice.log` type |
| `mitre` (single text, proposed) | `threat.framework` + `threat.tactic.id/name` + `threat.technique.id/name` (+ sub-technique) | `attacks[]` (tactic/technique/sub-technique objects) | `rule.mitre{id[], tactic[], technique[]}` — arrays | (ES `threat.*` enrichment, not core CIM) | — |
| `session_id` | — (no core ECS session field on base event) | `session.uid` object | — | `session_id` **exact match** (Net_Traffic) | `uid` is per-*connection*, not session |
| `protocol` (packets) | Split: `network.transport` (tcp/udp) + `network.protocol` (L7: http/dns) + `network.type` (ipv4/ipv6) | `traffic.proto_name` etc. / connection info | `data.protocol` (decoder-specific) | Split ⚠️ opposite to ECS: `transport`=L4, `protocol`=**L3** (`ip`), `app`=L7 | Split: `proto` (L4) + `service` (detected L7) + `ip_proto` (number) |
| `length` (packets) | `network.bytes` / `source.bytes`+`destination.bytes` | `src_endpoint.bytes` / totals | — | `bytes` (=`bytes_in`+`bytes_out`) | Split: `orig_bytes` / `resp_bytes` (+ `*_ip_bytes`, `*_pkts`) |
| `payload` (packets) | no ECS equivalent stored per packet | `raw_data` analogue only | `full_log` analogue only | `_raw` | **not stored** — Zeek logs metadata, extracts files separately |

#### 1.1 ECS — Elastic Common Schema

Official basis: Elastic Security requires *every* event to carry `@timestamp`, `ecs.version`, `event.kind`, `event.category`, `event.type`; host display relies on `host.name`/`host.id`; authentication display relies on literally `event.category:authentication` with `event.outcome:success|failure` and `user.name`; network display relies on `source.ip`/`destination.ip`. [Elastic SIEM field reference, verified live]

| Project field | Verdict | Detail |
|---|---|---|
| `timestamp` | ⚠️ Concept aligns, format/type differ | ECS `@timestamp` is type `date`, example `2016-05-23T08:05:34.853Z`. ECS also distinguishes `@timestamp` (when it occurred) < `event.created` (agent first saw it) < `event.ingested` (arrived in central store). Project has only one, as local TEXT — sorting/comparison and delay measurement are impossible to do reliably. |
| `event_source` (auth/system/host) | ❌ Wrong axis | Those values mix *where it came from* with *what it is*. ECS separates them: provenance = `event.module`/`event.dataset` (e.g. `apache.access`)/`event.provider` (e.g. `kernel`, Sysmon); classification = `event.category`. `host` as a *source value* also collides with `host` as the machine field. |
| `event_type` (login_success, login_failure, sudo…) | ❌ Missing 2 of 3 levels | ECS categorisation is 4 fields: `event.kind` (`alert\|event\|metric\|state\|pipeline_error\|signal`) → `event.category` (closed list: `authentication, configuration, database, driver, file, host, iam, intrusion_detection, malware, network, package, process, registry, session, web`; array type) → `event.type` (closed sub-bucket list: `access, admin, allowed, change, connection, creation, deletion, denied, end, error, group, info, installation, protocol, start, user`; array) → `event.action` (keyword, implementer-defined, *more specific than category*: `group-add`, `process-started`, `user-password-change`). `login_success` fuses category+action+outcome into one string, so "all authentication events" and "all failures" each need string parsing. Moving outcome out (project already has `outcome` — good) leaves `login` as the action. [ECS Event fields, verified live] |
| `outcome` | ✅ Fully aligns | ECS `event.outcome` closed values are exactly `failure, success, unknown`. Project's `success/failure` just needs `unknown` added — do not invent `partial`/`error` here. |
| `severity` TEXT | ⚠️ Label aligns, type differs | ECS `event.severity` is type `long` — *"the numeric severity of the event according to your event source"*; the source defines what numbers mean, but it is numeric so it can be thresholded/sorted. A text-only scale cannot do `severity >= high` without a CASE expression everywhere. |
| `user_name`, `host`, `src_ip` | ✅ Concept, ❌ spelling/nesting | ECS: `user.name`, `host.name`, `source.ip`, `destination.ip`, `source.port`, `destination.port` — dotted names that become nested JSON objects, with types `keyword`/`ip`/`long`. In SQLite the dots are meaningless; keep the *semantics* (source vs destination, not src vs dst asymmetry) and publish the mapping (§3.3). Also missing ECS companions that cost nothing: `user.id`, `host.id`, `destination.ip/port` on events (not just packets). |
| `raw` | ✅ Fully aligns | ECS `event.original` = *"raw text message of entire event… demonstrate log integrity"*, deliberately not indexed. OCSF/Wazuh agree (below). Keep it out of indexes/FTS-by-default. |
| `message` | ✅ Aligns | ECS base `message`. Keep distinct from `raw` (see OCSF's explicit warning, §1.2). |
| alerts: `mitre` single TEXT | ⚠️ Direction right, shape too flat | ECS threat set is structured: `threat.framework` (example `MITRE ATT&CK`), `threat.tactic.id`, `threat.technique.id` (+ `.name`, `.reference`, sub-technique). One free-text column can't hold tactic + technique + sub-technique, and can't be validated against `T####[.###]` format. Minimum professional shape = 3 columns (§3.2). |
| alerts: no rule fields | ❌ Missing | ECS `rule.id` (*"unique within the scope of an agent/observer"*, keyword), `rule.name`, `rule.description`, `rule.category` capture *which detection fired*. `alert_type` conflates rule name + event type and is not stable if someone rewords it. Alerts in ECS are also just events with `event.kind=alert` — the project's separate `alerts` table is fine at SQLite scale, but should link back to evidence (§2). |
| — | Types note | ECS field *types* are the transferable part: timestamps = date, IPs = ip (validate/store canonical text in SQLite), ports/bytes/severity = integer, identifiers/names = keyword (exact-match, not full-text). SQLite has no ip/date types — enforce in the writer (§3.1). |

#### 1.2 OCSF — Open Cybersecurity Schema Framework (v1.9)

Official basis: schema.ocsf.io class pages, verified live for Authentication [3002].

| Aspect | OCSF | Project comparison |
|---|---|---|
| Event classification | Three integer IDs + string siblings: `category_uid`/`category_name`, `class_uid`/`class_name`, `activity_id`/`activity_name`; `type_uid = class_uid*100 + activity_id`. Categories: 1 System Activity, 2 Findings, 3 Identity & Access Management, 4 Network Activity, 5 Discovery, 6 Application Activity. Classes the project needs: `3002` Authentication (activity 1 Logon, 2 Logoff, 7 Account Switch — the latter is exactly `sudo`/`su`), `3001` Account Change, `1007` Process Activity, `1001` File System Activity, `4001` Network Activity, `2004` Detection Finding (= an alert). | ❌ Project's `event_source`+`event_type` cannot express this. But ✅ the *pattern* is copyable for free: a broad category column + a specific action column (§3.1). Do **not** copy the numeric UIDs — they only pay off if actually exporting OCSF JSON. |
| Severity | `severity_id` **Required, Integer**: `0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal, 99 Other`, with `severity` as its string sibling — *"for all other values, this should match the caption defined for that severity_id"*. Dual representation is deliberate: sort/filter on the int, display the label. | ❌ Project has only the label, and its label set omits `critical` (and `unknown`). This is the single highest-value fix: adopt OCSF's 0–5 scale verbatim (§3.1) — it also maps cleanly to Splunk's `critical/high/medium/low/informational/unknown` and collapses Wazuh's 0–16 (below). |
| Outcome vs status vs disposition — three different things OCSF keeps apart | (a) Event outcome: `status_id` 0 Unknown / 1 Success / 2 Failure + `status` sibling. (b) Finding/alert workflow status (Detection Finding): `status_id` 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other. (c) `disposition_id`: what the *security product* did (Blocked, Allowed, Logged, Quarantined…). Plus `verdict_id` for true/false-positive judgement on close. | ⚠️ Project conflates (a) into `event_type` on events (fixed by `outcome`) and — in the proposed alerts additions — puts `false_positive` inside `status` (`open/acknowledged/resolved/false_positive`). OCSF's separation says: `false_positive` is a **verdict/disposition on closure**, not a workflow state. Keep `status` = open/acknowledged/resolved and add a separate closure/verdict value, or at minimum document that `false_positive` is terminal-with-verdict. Project has no (c) at all — acceptable; add only if a blocking action ever exists. |
| Actors/endpoints | Objects: `actor` (user/process that initiated), `user`, `src_endpoint{ip,port}`, `dst_endpoint{ip,port}`, `device`/`host`, `service`, `session`. Authentication class: `dst_endpoint` is *"the endpoint to which the authentication was targeted"* — i.e. the target host is a first-class field. | ❌ Events have `src_ip` but **no destination at all**; alerts likewise. A login event without the target host/service can't answer "failures against *which* host?" Add `dst_ip`, `dst_port`, `host_name` (target/observed host) to both. |
| Raw + message | `raw_data` = *"original event data… verbatim log line… not intended for structured querying"*; `message` = *"concise, meaningful summary suitable for display — not a raw log line"*, e.g. `"User john_doe logged in from 10.0.0.1"`. Also `raw_data_hash` for integrity/dedup. | ✅ `raw`+`message` pair already matches this exactly — keep both, enforce the distinction. `raw_data_hash` (sha256 of raw) is a cheap optional add for dedup. |
| Identity / provenance | `metadata` **Required**: `metadata.product` (data source), `metadata.version` (schema version); each event also has a `uid` in `metadata`/finding `finding_info.uid` that *"stays the same across exports so a SIEM can correlate an update or close"*. `observables[]` surfaces IOCs (each entry references e.g. `src_endpoint.ip` with type+value) for correlation without parsing the event. | ⚠️ Project rowid `id` is unique only inside this DB file and is reused semantics-free; no schema-version marker anywhere. Add `event_uid` (UUID) + a `schema_version` constant/default. Skip `observables[]` — in a relational table, the columns *are* the observables. |
| Time | `time` = event time (epoch ms), plus `start_time`/`end_time` for aggregates/durations, `finding_info.first_seen_time`/`last_seen_time` for findings. | ⚠️ Same single-timestamp gap as ECS. For alerts, first_seen/last_seen + count is how professionals represent *repeated* alerts instead of one row per brute-force attempt (cf. Wazuh `firedtimes`). |

#### 1.3 Wazuh — `wazuh-alerts-*` document structure

Official basis: Wazuh docs — rules classification (verified live), SSH brute-force worked alert (verified live), MITRE + archives/global config (index).

Anatomy of a real alert (rule 5710, sshd invalid user):

```json
{ "timestamp": "2019-10-15T19:07:57.741+0000",
  "rule": { "level": 5, "description": "sshd: Attempt to login using a non-existent user",
            "id": "5710", "firedtimes": 7, "mail": false,
            "groups": ["syslog","sshd","invalid_login","authentication_failed"],
            "pci_dss": [...], "gdpr": [...], "hipaa": [...], "nist_800_53": [...] },
  "agent": {"id": "001", "name": "linux-agent"},
  "manager": {"name": "wazuh-manager-master-0"},
  "id": "1571166477.30198",
  "cluster": {"name": "wazuh", "node": "wazuh-manager-master-0"},
  "full_log": "Oct 15 21:07:56 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928",
  "predecoder": {"program_name": "sshd", "timestamp": "...", "hostname": "linux-agent"},
  "decoder": {"parent": "sshd", "name": "sshd"},
  "data": {"srcip": "18.18.18.18", "srcport": "48928", "srcuser": "blimey"},
  "location": "/var/log/auth.log" }
```
MITRE-enriched rules add `rule.mitre: {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}` (arrays — a rule can map to several techniques).

| Aspect | Verdict vs project |
|---|---|
| `rule.level` 0–16 | Wazuh's scale is fine-grained because it doubles as *alerting threshold*: levels 0 Ignored, 1–2 below dashboard, 3 Successful/Authorized, 5 User-generated error, 10 Multiple user errors, 12 High-importance, 14 attack (usually correlation), 15 Severe attack, 16 max (custom only). Default `log_alert_level=3` decides what even becomes an alert. ❌ Project text severity can't express thresholding (`WHERE severity_id >= X`). ✅ But do **not** copy 0–16 — 17 grades no small team can assign consistently. Collapse to OCSF 0–5 (§3.4 mapping table). |
| `rule.id` + `rule.description` + `rule.groups[]` | ❌ The project's biggest alerts gap after severity. Wazuh alerts are *rule-centric*: stable numeric id, human description, and a tag-like group list (which doubles as classification + compliance mapping). Project equivalent should be `rule_id` + `rule_name` + optional `rule_groups` (comma/JSON text). Renaming/rewording a rule must not orphan history — hence id *and* name. |
| `agent{id,name}` + `manager.name` | ⚠️ Project `host` (events) is a start; alerts have **no host/agent at all**. Every Wazuh alert answers "on which monitored host, reported to which manager" before anything else. Add `host_name` to alerts. Agent *id* only matters with >1 host — keep name now, id later. |
| `decoder.name` + `location` + `predecoder.program_name` | ⚠️ = "which parser/source file produced this". Project `event_source` is a coarser version of this. Rename/repurpose it to provenance: `source_type`/`app` (sshd, sudo, app, kernel…) + optionally `source_file`. See §3.1. |
| `data.srcip/srcuser/dstuser` | Note Wazuh distinguishes `srcuser` (who attempted) from `dstuser` (account targeted — e.g. brute-forcing `root` from user `blimey`'s session). Project has one user column; for auth events the *target* account is usually the interesting one. At minimum document which one `user_name` means; ideally `user_name` (target/actor per CIM, §1.4) + `src_user_name` nullable for sudo/priv-esc (actor before escalation). |
| `id: "1571166477.30198"` | Wazuh alert id = epoch + counter — globally unique and roughly time-ordered. Reinforces §2 point on UIDs. |
| `firedtimes` + composite rules | Rule 5712 (level 10) fires only when 5710 fires 8×/120s from same source. Professional alerts therefore carry aggregation context. Cheap SQLite version: `event_count`/`first_seen`/`last_seen` on alerts, or leave alerts 1:1 and do correlation in queries — but say which. |
| Archives vs alerts model | By default Wazuh indexes **only alerts** (events matching a rule ≥ threshold); storing *all* events requires `logall`/`logall_json` → `wazuh-archives-*`, off by default because of disk cost. ✅ The project's design — `events`/`app_logs` (all) + `alerts` (matched) — already mirrors alerts-vs-archives correctly. This is a genuine alignment worth stating: keep the separation, don't merge alerts into events. |

#### 1.4 Splunk CIM — Authentication & Network_Traffic

Official basis: CIM Authentication and Network_Traffic data-model references, both verified live (help.splunk.com, CIM 8.8).

**Authentication model** — fields: `action` (prescribed `success|failure|pending|error`), `app` (`ssh`, `splunk`, `win:local`…), `src`, `dest`, `user`, `src_user`, `user_id`, `signature`, `signature_id`, `authentication_method`, `authentication_service`, `duration`, plus inherited `host`, `source`, `sourcetype`. Datasets are selected by **tags/eventtypes** (`tag=authentication`, with `Failed_Authentication`/`Successful_Authentication` as constrained subsets), not by a category column value alone.

**Network_Traffic (`All_Traffic`)** — fields: `action` (`allowed|blocked|teardown`), `app` (L7 protocol), `bytes`, `bytes_in`, `bytes_out`, `dest`, `dest_ip`, `dest_port`, `src`, `src_ip`, `src_port`, `transport`, `protocol`, `direction`, `duration`, `dvc`, `flow_id`, `packets*`, `rule`, `rule_id`, `session_id`, `tcp_flag`, `ttl`, `user`, `vendor_product`.

| Aspect | Verdict vs project |
|---|---|
| Naming | ✅ **Project is already CIM-shaped where it matters most for packets:** `src_ip`, `src_port`, `dest_port` are literal CIM Network_Traffic names; CIM Authentication's `user` ≈ project `user_name`/`username`, and CIM explicitly *aliases* `src` from `src_ip`/`src_host` and `dest` from `dest_ip`/`dest_host`. Lesson: CIM itself is an aliasing layer over vendor names — professionals don't rename at ingest, they alias at search. Direct support for the views strategy in §4. Note project uses `dst_*` where CIM uses `dest_*` (`dst_ip`, `dst_port` in existing tables vs CIM `dest_ip`, `dest_port`) — the one spelling worth fixing in new tables / views, since `dest_*` is common to CIM *and* ECS `destination.*`. |
| `action` collision ⚠️ | In CIM **Authentication**, `action` means the *outcome* (`success/failure`); in CIM **Network_Traffic**, `action` means the *device decision* (`allowed/blocked/teardown`); in ECS, `event.action` means *what happened* (`login`, `process-started`) and outcome is `event.outcome`. Three standards, three meanings for "action". Project's separate `outcome` column (ECS/OCSF style) is the right choice — **do not rename `outcome` → `action`** to look CIM-like. If CIM export is ever needed, map `outcome AS action` in the Authentication view. |
| `app` | ❌ Missing from events. CIM `app` = the application/service involved (`ssh`, `sudo`, the web app name). It is the field that lets one events table serve auth+system+host without `event_source` doing triple duty. Add `app`. |
| `signature` / `signature_id` | = CIM's rule identity pair (human name + stable id/code) — same gap as ECS `rule.*`/Wazuh `rule.id`, third independent confirmation. |
| Tag/eventtype approach | CIM classifies by *tagging at search/model time*, not by storing a taxonomy in every row. SQLite analogue: keep stored columns minimal (`event_category`, `event_action`) and define saved queries/views (`v_authentication`, `v_failed_authentication`) as the "data model". Zero storage cost. |
| `protocol` trap ⚠️ | CIM: `protocol` = L3 (`ip`), `transport` = L4 (`tcp/udp/icmp`), `app` = L7. ECS is different again: `network.transport` = L4, `network.protocol` = **L7**. Zeek: `proto` = L4, `service` = L7, `ip_proto` = L3 number. The project's single packets `protocol` column therefore matches *none* of them unambiguously. Fix for new work: `transport` (tcp/udp/icmp) + `service`/`app` (detected L7) — see §1.5. |

#### 1.5 Zeek `conn.log` vs the `packets` table

Official basis: Book of Zeek conn.log reference, verified live — example row:
`{"ts":1591367999.43, "uid":"C5bLoe2Mvxqhawzqqd", "id.orig_h":"192.168.4.76", "id.orig_p":46378, "id.resp_h":"31.3.245.133", "id.resp_p":80, "proto":"tcp", "service":"http", "duration":0.254, "orig_bytes":77, "resp_bytes":295, "conn_state":"SF", "missed_bytes":0, "history":"ShADadFf", "orig_pkts":6, "orig_ip_bytes":397, "resp_pkts":4, "resp_ip_bytes":511, "ip_proto":6}`

**Fundamental unit mismatch (state this before any field comparison): Zeek logs one row per *connection/flow*, the project logs one row per *packet*.** Most "missing fields" below are flow aggregates that a per-packet table cannot have at insert time — they belong on a derived `connections`/`flows` view/table (§4), not as new packet columns.

| Zeek field | In packets? | Assessment |
|---|---|---|
| `ts` epoch float | `timestamp` TEXT | Same instant, worse type: epoch/TEXT-ISO both sort only if format is disciplined; Zeek also shows sub-second precision matters for ordering packets. |
| `uid` — unique connection ID, joins `conn`↔`http`↔`dns`↔`files` logs | `session_id` (partial) | ✅ Concept present. ❌ If `session_id` is an auth/web session rather than a network 5-tuple flow id, the two are being conflated — CIM also has `session_id` *and* `flow_id` as separate fields. Name the network one `flow_id`/`conn_uid` in any new flow table; keep `session_id` for auth sessions. A Zeek-style uid is generated (opaque, ~18 chars), not sequential. |
| `id.orig_h/port`, `id.resp_h/port` | ✅ `src_ip/src_port/dst_ip/dst_port` | Full alignment in substance. Zeek's orig/resp vocabulary encodes *initiator vs responder*, which is more precise than src/dst when a reply packet flips src/dst — worth a doc note: define `src_*` = connection originator consistently, not per-packet sender, in any flow rollup. |
| `proto` (tcp/udp/icmp) | `protocol` (ambiguous) | See §1.4 trap. |
| `service` — *detected* L7 (http/dns/ssl/ssh), from payload inspection, may differ from port guess | ❌ Missing | **Highest-value packets gap.** Port 443 ≠ TLS necessarily; `service` is what makes traffic searchable by application. Cheap version: derive from port map at insert (`dst_port→service`) and label it as guessed, or leave NULL until DPI exists — but reserve the column in the flow view. |
| `duration` (float seconds) | ❌ Missing (flow-level) | Derivable: `MAX(timestamp)-MIN(timestamp)` per flow. Needed for beaconing/exfil/long-session detection; Splunk CIM also has `duration` on both models. |
| `orig_bytes` / `resp_bytes` (payload bytes, directional) | `length` (single, per packet, directionless) | ❌ Directional byte split is what detects exfiltration (small request, huge response — or reverse). Derivable in flow rollup: `SUM(length) GROUP BY direction`. Also `orig_pkts/resp_pkts`, `orig_ip_bytes/resp_ip_bytes` (IP-level incl. headers vs payload bytes — project `length` should document which it is). |
| `conn_state` (SF normal, S0 SYN-no-reply = scan/dead host, REJ rejected/RST, RSTO/RSTR reset, OTH other) + `history` (e.g. `ShADadFf`) | `flags` (per packet, partial) | ❌ Per-packet TCP flags cannot answer "did this connection complete?" without reassembly logic in every query. `conn_state` is a *derived flow verdict* — compute in the flow view from flags (SYN-only → S0-like, SYN+FIN/ACK completion → SF-like, RST → REJ/RST-like). This one derived column replaces the most analyst SQL. |
| `local_orig`/`local_resp`, `missed_bytes`, `tunnel_parents` | ❌ Missing | Skip: `missed_bytes` is sensor-health (no capture-loss concept in this app); local/remote is derivable from a private-IP check at query time. |
| `payload`, `checksum`, `ttl` (project-only) | n/a in Zeek | Zeek deliberately does **not** store payload in conn.log (files/content are separate logs). Project storing raw `payload` per packet is a privacy/size liability no professional reference endorses in the metadata table — recommend: cap/truncate, hash, or move to a separate blob table (§3.5). `checksum` has near-zero detection value (and is often offload-invalid); `ttl` is a minor fingerprinting signal — keep if free, index neither. |

---

### 2. Gap list ranked by professional value

| # | Gap | Why professionals care (evidence) | Cost to fix |
|---|---|---|---|
| 1 | **Timestamp discipline**: single local TEXT `timestamp` | Every standard separates event time from ingestion time (ECS `@timestamp` < `event.created` < `event.ingested`; OCSF `time` + metadata; Wazuh indexed `@timestamp`) and stores a sortable, unambiguous instant. Local text breaks ordering across DST/timezones, range queries, and correlation with any external log. | Trivial: store ISO-8601 UTC `YYYY-MM-DDTHH:MM:SS.sssZ` text (sorts lexicographically = chronologically in SQLite) + add `ingested_at` defaulting to insertion time. |
| 2 | **Text-only severity, missing `critical`** | ECS `event.severity` is long; OCSF `severity_id` 0–5 is Required; Wazuh thresholds on `rule.level`; Splunk prescribes `critical…informational`. Text can't threshold, and inconsistent spellings (`High`/`HIGH`/`med`) silently break filters. | Trivial: `severity_id INTEGER` (OCSF 0–5) as source of truth + generated/display label. Mapping in §3.4. |
| 3 | **No category / action split** (`event_type=login_failure` fuses 3 axes; `event_source` mixes provenance) | ECS kind/category/type/action, OCSF category/class/activity, CIM dataset+tag, Wazuh decoder+groups all separate *bucket* from *specific action* from *outcome*. Without it, "all auth events", "all failures", "all sudo" are three string hacks. | Low: split into `event_category` + `event_action`, keep `outcome` separate, repurpose source → `app`/`source_type`. Controlled vocabularies in §3.1. |
| 4 | **Alerts have no stable rule identity** (`alert_type` only) | Independently required by ECS (`rule.id`+`rule.name`), Wazuh (`rule.id`+`description`+`groups`), CIM (`signature_id`+`signature`). Rewording a description must not break history/dedup/stats. | Low: add `rule_id TEXT`, `rule_name TEXT`; backfill `rule_id = alert_type` slug. |
| 5 | **Alerts lack destination + target + evidence link**: only `src_ip`; no `dst_ip/host/user`, no FK to event/packet/session that caused it | Wazuh alerts carry agent + `data.*` endpoints + `full_log`; OCSF findings carry endpoints + `finding_info.related_events`; ECS alert display uses source *and* destination. An alert you cannot pivot from to evidence forces a manual timestamp hunt. | Low: add `dst_ip`, `dst_port`, `user_name`, `host_name`, `event_id` (FK → events.id, nullable for packet-derived alerts) to alerts. |
| 6 | **MITRE as one free-text column** | ECS `threat.framework/tactic/technique`, OCSF `attacks[]`, Wazuh `rule.mitre{}` all structure it; technique IDs are validated patterns (`T1110`, `T1110.001`). | Low: split to `mitre_tactic`, `mitre_technique_id`, `mitre_technique_name` (+ framework constant `MITRE ATT&CK` implied). |
| 7 | **No unique event UID / schema version** (rowid only) | ECS `event.id`, OCSF `metadata.uid`/`finding_info.uid`, Wazuh `id`, Zeek `uid` — dedup on re-ingest, cross-store correlation, and alert↔event linking all assume one. Rowids don't survive export/merge. | Low: `event_uid TEXT UNIQUE` (UUID4 at writer) on events; keep integer PK for joins. Add `schema_version` default. |
| 8 | **Alert lifecycle conflates verdict with status** (`false_positive` as a status) + no `acknowledged_by` | OCSF separates finding status (New/In Progress/Suppressed/Resolved) from verdict (false positive) and disposition. Also: who acked/resolved is basic auditability; project already has `resolved_at` + `notes` (✅ good) but not the actor. | Trivial: keep status set, treat `false_positive` as terminal verdict (or move to `verdict` column), add `acknowledged_by`/`resolved_by` reusing `users`. |
| 9 | **Packets: no flow-level service / duration / conn_state / directional bytes** | Zeek §1.5 — these four derived facts answer most network-detection questions; per-packet flags/length cannot. | Medium: don't add columns — add a `connections` rollup view/table (§4). Reserve `service` derivation. |
| 10 | **No `app` / provenance granularity on events**; `detail`/`payload` untyped blobs | CIM `app`, ECS `event.dataset/provider`, Wazuh `decoder.name`+`location`. Also: professionals keep structured fields queryable and blobs (`event.original`/`full_log`/`raw_data`) explicitly unindexed. | Low: add `app`; document `raw`/`detail`/`payload` as evidence-only, exclude from routine indexes. |
| 11 | Naming drift `dst_*` vs `dest_*`, `username` vs `user_name` across own tables | CIM aliases prove drift is normal — *if* documented/aliased. Undocumented drift inside one DB is just bugs waiting. | Trivial: standardise new columns on `dst_*`→ keep? — recommendation: keep existing `dst_*` in old tables (don't break app), use `dest_*` only if starting fresh; **either way publish the crosswalk (§1.0) in the repo and alias in views.** Consistency within the DB beats matching any external spelling. |
| — | Explicit non-gaps (already professional) | Separate alerts vs all-events tables (= Wazuh alerts vs archives); `raw` retained (= ECS/OCSF/Wazuh unanimous); `outcome` as its own column with success/failure; alerts gaining `status/notes/resolved_at` lifecycle; `session_id` correlation concept (= CIM/Zeek uid pattern). | — |

---

### 3. Revised professional-grade schema (SQLite-appropriate)

#### 3.1 Revised `events` table

Design rules applied: flat `snake_case` columns (no dots — SQLite identifiers with dots mean table.column); numeric IDs for anything filtered/sorted/thresholded, with text labels derived, never stored twice inconsistently (exception: `severity` label omitted entirely — derive in UI/view from `severity_id`); timestamps as ISO-8601 UTC TEXT; controlled vocabularies enforced with `CHECK` constraints (SQLite's substitute for Elasticsearch mappings / OCSF enums).

```sql
CREATE TABLE events (
  id            INTEGER PRIMARY KEY,
  event_uid     TEXT NOT NULL UNIQUE,               -- UUID4, ECS event.id / OCSF metadata.uid analogue; dedup + export identity
  timestamp     TEXT NOT NULL,                      -- EVENT time, ISO 8601 UTC: 2026-11-23T09:31:34.123Z  (= ECS @timestamp)
  ingested_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),  -- ECS event.ingested; writer/import time
  schema_version TEXT NOT NULL DEFAULT '1.0',       -- ECS ecs.version / OCSF metadata.version analogue

  -- Classification: three axes, never fused (ECS category/type/action; OCSF category/class/activity)
  event_category TEXT NOT NULL CHECK (event_category IN
                 ('authentication','iam','system','host','network','process','file','configuration','application')),
                                                    -- ECS event.category subset relevant to this project
  event_action   TEXT NOT NULL,                     -- ECS event.action, implementer-defined, outcome-free:
                                                    --   login, logout, sudo, user_create, password_change, service_start, ...
  event_type     TEXT CHECK (event_type IN ('access','admin','change','connection','creation','deletion','denied','end','error','info','start','user')),
                                                    -- OPTIONAL ECS event.type sub-bucket; NULL is acceptable
  outcome        TEXT CHECK (outcome IN ('success','failure','unknown')),  -- ECS event.outcome / OCSF status_id; NULL if N/A
  severity_id    INTEGER NOT NULL DEFAULT 1 CHECK (severity_id BETWEEN 0 AND 5),
                                                    -- OCSF severity_id: 0 unknown,1 informational,2 low,3 medium,4 high,5 critical

  -- Provenance (replaces event_source auth/system/host, which mixed axes)
  source_type    TEXT NOT NULL,                     -- auth | system | host | app  (coarse origin, keep for compat)
  app            TEXT,                              -- CIM app / ECS event.provider: sshd, sudo, plexus-app, kernel, systemd...

  -- Actor / target (CIM: src_user = initiator in priv-esc, user = target/primary)
  user_name      TEXT,                              -- ECS user.name / CIM user
  src_user_name  TEXT,                              -- CIM src_user; only for sudo/su/priv-esc (who escalated)
  user_id        INTEGER REFERENCES users(id),      -- nullable FK when the user is a local account

  -- Endpoints (both sides, always)
  src_ip         TEXT, src_port INTEGER CHECK (src_port BETWEEN 0 AND 65535),
  dst_ip         TEXT, dst_port INTEGER CHECK (dst_port BETWEEN 0 AND 65535),
  host_name      TEXT,                              -- ECS host.name / Wazuh agent.name: host where event occurred / was targeted

  session_id     TEXT,                              -- auth session correlation (keep existing semantics; NOT a network flow id)
  message        TEXT,                              -- concise human summary (OCSF message) — not the raw line
  raw            TEXT,                              -- ECS event.original / OCSF raw_data / Wazuh full_log; evidence only, do not index
  raw_hash       TEXT,                              -- OPTIONAL sha256(raw) for dedup/integrity (OCSF raw_data_hash)
  detail         TEXT                               -- OPTIONAL structured extras as JSON text (from app_logs.detail); validate with json_valid() if used
);
CREATE INDEX idx_events_ts        ON events(timestamp);
CREATE INDEX idx_events_cat_act   ON events(event_category, event_action, timestamp);
CREATE INDEX idx_events_src_ip    ON events(src_ip, timestamp);
CREATE INDEX idx_events_user      ON events(user_name, timestamp);
CREATE INDEX idx_events_severity ON events(severity_id, timestamp);
-- Deliberately NO index on raw / message / detail.
```

What changed vs the proposal, and why: `event_source` → split into `source_type` (compat) + `app` (useful); `event_type(login_success)` → `event_category=authentication` + `event_action=login` + `outcome=success` (the proposal's own `outcome` column made the fused value redundant); `severity` text → `severity_id` int (label derived, §3.4); `user_name` kept (not renamed to ECS `user.name` — see §3.3) + `src_user_name` for sudo; added `dst_ip/dst_port`, `ingested_at`, `event_uid`, `schema_version`; `host` → `host_name` (explicit, matches ECS `host.name` semantics and Wazuh `agent.name` role).

Example rows under old → new: `login_failure` → `authentication / login / failure`; `sudo` → `iam (or authentication) / sudo / success`, `user_name`=target account, `src_user_name`=invoking user; a service crash → `system / service_stop / failure`, severity per impact.

#### 3.2 Revised `alerts` additions

Keep existing `id, timestamp, src_ip, alert_type, description, session_id` (don't break the app — §4) and add:

```sql
ALTER TABLE alerts ADD COLUMN ingested_at   TEXT;  -- + backfill/default as events
ALTER TABLE alerts ADD COLUMN severity_id   INTEGER CHECK (severity_id BETWEEN 0 AND 5);  -- OCSF scale, §3.4; derive label in UI
-- Rule identity (ECS rule.* / Wazuh rule.* / CIM signature*)
ALTER TABLE alerts ADD COLUMN rule_id       TEXT;  -- stable, never reworded: e.g. 'auth.brute_force', 'sshd.invalid_user'
ALTER TABLE alerts ADD COLUMN rule_name     TEXT;  -- human name; alert_type becomes an alias of this during migration
ALTER TABLE alerts ADD COLUMN rule_groups   TEXT;  -- Wazuh rule.groups analogue: comma list or JSON array text, e.g. 'authentication,brute_force'
-- Pivot fields (both endpoints + target + host + evidence)
ALTER TABLE alerts ADD COLUMN dst_ip        TEXT;
ALTER TABLE alerts ADD COLUMN dst_port      INTEGER;
ALTER TABLE alerts ADD COLUMN user_name     TEXT;
ALTER TABLE alerts ADD COLUMN host_name     TEXT;
ALTER TABLE alerts ADD COLUMN event_id      INTEGER REFERENCES events(id);  -- evidence link; NULL for packet-derived alerts
ALTER TABLE alerts ADD COLUMN event_count   INTEGER NOT NULL DEFAULT 1;     -- Wazuh firedtimes analogue
ALTER TABLE alerts ADD COLUMN first_seen    TEXT;  -- = timestamp for count=1; OCSF finding first_seen_time
ALTER TABLE alerts ADD COLUMN last_seen     TEXT;  -- OCSF finding last_seen_time
-- MITRE structured (replaces single `mitre` text; keep `mitre` column during migration as technique_id alias)
ALTER TABLE alerts ADD COLUMN mitre_tactic          TEXT;  -- e.g. 'Credential Access' (+ optionally tactic id TA0006 in same/next col)
ALTER TABLE alerts ADD COLUMN mitre_technique_id    TEXT CHECK (mitre_technique_id IS NULL OR mitre_technique_id GLOB 'T[0-9][0-9][0-9][0-9]*');
                                                           -- e.g. 'T1110' or 'T1110.001'
ALTER TABLE alerts ADD COLUMN mitre_technique_name  TEXT;  -- e.g. 'Brute Force' / 'Password Guessing'
-- Lifecycle (proposal's columns, with verdict separated in meaning)
--   status TEXT CHECK IN ('open','acknowledged','resolved','false_positive')  -- keep proposal's set for compat;
--        DOCUMENT: false_positive is a terminal verdict, not a workflow step (OCSF verdict vs status).
ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT;  -- username from users table
ALTER TABLE alerts ADD COLUMN resolved_by     TEXT;
--   resolved_at, notes: as proposed — keep.
```

If a greenfield alerts table were allowed, the cleaner form is `status IN ('open','acknowledged','resolved')` + `verdict IN ('true_positive','false_positive','benign','duplicate')` set only on closure (OCSF Detection Finding pattern). The proposal's 4-value status is acceptable if documented as above — do not let it grow further (`in_progress`, `pending_vendor`… belong in notes until there's a real workflow).

Severity on alerts vs events: alert `severity_id` is the *rule's* severity (Wazuh `rule.level` role); event `severity_id` is the *event's*. They will often differ (a low event feeding a high correlation alert) — that is correct and professional, not duplication.

#### 3.3 Naming decision — explicitly

| Option | Decision | Reason |
|---|---|---|
| Rename columns to ECS dots: `"source.ip"`, `"event.category"` | ❌ **Do not** | Dots in SQLite require permanent double-quoting, fight Python dict/ORM conventions, and buy nothing without Elasticsearch. ECS itself renders dots as *nested JSON*, which SQLite columns are not. |
| Rename to Splunk CIM (`src`, `dest`, `user`) | ❌ Do not | `src`/`dest` are *less* explicit than `src_ip`/`dst_ip`, collide with Splunk's own `source`, and CIM is designed as an alias layer, not a storage schema. |
| Keep flat snake_case + publish crosswalk + export views | ✅ **Do this** | `src_ip` already equals CIM Network_Traffic; every standard can be produced from the flat columns by a view (§4). Document the §1.0 crosswalk in the repo as the schema's mapping contract. If ECS/OCSF JSON export is ever built, it is a serializer over these columns, not a rename. |

#### 3.4 Severity mapping (one table to rule them all)

| Project `severity_id` | Label (UI only) | ECS `event.severity` | Wazuh `rule.level` | Splunk `severity` | Syslog (app_logs `level` analogue) |
|---|---|---|---|---|---|
| 0 | unknown | source-defined | 0–1 | unknown | — |
| 1 | informational | " | 2–3 | informational | info / notice |
| 2 | low | " | 4–6 | low | warning |
| 3 | medium | " | 7–10 | medium | error |
| 4 | high | " | 11–13 | high | critical |
| 5 | critical | " | 14–16 (docs: 16 max, custom-only) | critical | alert / emergency |

Existing text values map 1:1 except: proposal had no `critical` — existing `high` rows stay `4`; reserve `5` for "severe attack, no false-positive chance" (Wazuh 15 semantics). `app_logs.level` should map through the syslog column, not be copied verbatim into `severity_id`.

#### 3.5 What NOT to copy — and why

| Professional feature | Skip because |
|---|---|
| Deep nesting / JSON documents (`{"source":{"ip":…}}`, OCSF objects, Wazuh `rule.mitre{[]}` documents) as *storage* | SQLite's strength is flat typed columns + indexes; nesting forces `json_extract` in every query and loses CHECK/index ergonomics. JSON only at export time, and for the one genuinely list-valued field (`rule_groups`) if needed. |
| Full ECS field set (~1000 fields: `cloud.*`, `os.*`, `process.parent.*`, geo/AS enrichment…) | 95% would be permanently NULL in a single-host project. ECS itself is a menu ("field sets you mix in"), not a checklist. Adopt ~25 fields (§3.1). |
| Elasticsearch mappings, keyword/text dual fields, index templates, ILM | No Elasticsearch. SQLite equivalents already used above: TEXT + CHECK + selective indexes + `raw` unindexed. |
| OCSF numeric UIDs (`category_uid`, `class_uid=3002`, `type_uid=300201`), `observables[]`, profiles/extensions | Payoff exists only for OCSF-JSON interchange with other OCSF tools. Storing both uid *and* name duplicates state and invites divergence. Revisit only if an OCSF export is actually shipped — then compute UIDs in the serializer from `event_category`/`event_action`. |
| Wazuh 0–16 levels, compliance arrays (`pci_dss[]`, `gdpr[]`, `nist_800_53[]` on every alert), decoders/predecoders, cluster/manager fields, Filebeat enrichment | Compliance mapping belongs on the *rule definition* (one row per rule in a rules table/config), not repeated on every alert row. Single-manager project has no cluster; decoder ≈ `app`. |
| Splunk data-model acceleration, tags/eventtypes machinery, `*_bunit/*_category/*_priority` asset-correlation fields | Those are Splunk-platform features, not schema. The portable part — alias views + a tag-like category — is already adopted. |
| Zeek per-connection logging as a replacement for `packets`, storing full `payload` | Different unit of analysis (§1.5). And payload-at-rest is a liability: cap payload length, store a hash + first-N-bytes, or split to a separate table with retention — do not let it grow unbounded in the hot table. |
| `event.risk_score` / risk scoring (ECS/Wazuh-adjacent) | A second severity-like number nobody can calibrate at this scale doubles triage confusion. One severity scale only. |

---

### 4. Migration note — gradual alignment without breaking the running app

SQLite makes this low-risk: `ALTER TABLE … ADD COLUMN` is cheap and old code ignores new columns; views provide the professional names while storage names stay stable. Sequence, each step independently shippable:

**Step 0 — Discipline before DDL (writer-only, no schema change).** In the Python writer: emit all new timestamps as ISO-8601 UTC (`datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')`); normalise severity text to the §3.4 label set; stop creating new fused `event_type` values. Existing rows are untouched; new rows are already clean. Add a one-off backfill script for old timestamps *only if* the old format is parseable unambiguously — otherwise leave old rows and note the cutover date (guessing timezones forensically is worse than a documented seam).

**Step 1 — Additive columns (the §3.1/§3.2 ALTERs, all nullable or defaulted).** Backfill: `events.severity_id` from text via §3.4 CASE; `alerts.rule_id` = slug of `alert_type`, `rule_name` = `alert_type`; `alerts.mitre_technique_id` = old `mitre` where it matches `T####*`, else leave NULL and copy the text to `mitre_technique_name`/notes for manual cleanup; `ingested_at` = `timestamp` for historical rows (documented approximation). Keep writing the old columns (dual-write) from the app.

**Step 2 — Compatibility / professional views (the alias layer, CIM-style).**

```sql
-- Old app keeps reading `alerts`; new queries and any export use the view.
CREATE VIEW v_alerts_ecs AS
  SELECT id,
         timestamp        AS "timestamp",          -- export serializer renames to @timestamp
         severity_id,                              -- serializer emits event.severity + label
         rule_id          AS "rule.id",
         rule_name        AS "rule.name",
         mitre_technique_id AS "threat.technique.id",
         mitre_tactic       AS "threat.tactic.name",
         src_ip           AS "source.ip",
         dst_ip           AS "destination.ip",
         user_name        AS "user.name",
         host_name        AS "host.name",
         status, resolved_at, notes
  FROM alerts;

CREATE VIEW v_authentication AS   -- CIM "data model" analogue: tag=authentication, action=outcome
  SELECT *, outcome AS cim_action, app AS cim_app, src_ip AS cim_src, host_name AS cim_dest
  FROM events WHERE event_category = 'authentication';

-- Zeek-style flow rollup over the untouched packets table (§1.5):
CREATE VIEW v_connections AS
  SELECT session_id AS conn_uid,
         MIN(timestamp) AS ts_start, MAX(timestamp) AS ts_end,
         (julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 86400.0 AS duration_s,
         src_ip, dst_ip, src_port, dst_port, protocol AS transport,
         SUM(length) AS total_bytes, COUNT(*) AS packet_count
         -- conn_state / orig_bytes / resp_bytes: add when packet direction relative to
         -- the originator is recorded; approximate conn_state from flags in a v2 view.
  FROM packets GROUP BY session_id, src_ip, dst_ip, src_port, dst_port, protocol;
```
Caveat to document: `v_connections` is only as good as `packets.session_id` — if that id is not a stable per-flow id, group by the 5-tuple + a time-gap heuristic instead, and say so.

**Step 3 — Cut readers over, then (optionally) stop dual-writing.** Move dashboards/queries to `severity_id`, `rule_id`, category/action. Only after no code references them, consider dropping/renaming legacy columns — in SQLite that means a table-rebuild migration; it is *optional*. Leaving `alert_type` as a deprecated alias of `rule_name` forever is a legitimate end-state (it is exactly what CIM field aliases are).

**Step 4 — New tables only where the unit differs.** If flow analysis becomes a real requirement, materialise `connections` (from `v_connections`, refreshed on session close) rather than widening `packets`. Do not backfill Zeek fields (`service`, `conn_state`) with fabricated values for historical packets — NULL/derived-only, labelled as derived.

Rollback at every step = drop the view / ignore the new columns; no step rewrites existing columns in place except the Step-1 backfills, which only populate previously-empty fields.

---

## Could not verify / open questions

- **Wazuh `rule.mitre` exact JSON shape on a current official page:** the worked official alert (v4.0 docs) predates MITRE enrichment and has no `rule.mitre`; the `{id[], tactic[], technique[]}` shape was corroborated in search results (Wazuh alert samples) and the official MITRE module page was found via index but not opened in full. Shape is widely consistent across samples; treat field names as high-but-not-live-verified confidence.
- **Mission brief vs current Wazuh docs:** brief states `rule.level` 0–15; current official classification page states 0–16 (16 = maximum, custom-rules only). Report follows current docs.
- **Project-internal unknowns the standards cannot answer:** what `packets.session_id` actually identifies (auth session vs network flow) — §1.5/§4 flag both readings; what `packets.length` counts (wire/IP/TCP-payload bytes); what timezone/format existing `timestamp` TEXT values use. Each affects backfill safety, none affects the revised design.
- ECS version cited: event-field definitions are from the ECS 1.10 reference (stable, long-standing definitions) cross-checked against the current Elastic Security SIEM field reference (ECS 9.x era); categorisation values have been stable across those versions, but a project pinning `schema_version`/`ecs.version` should pin one version explicitly.
- No live system was inspected: all project-schema facts are as stated in the mission brief.

## Sources

All read 2026-11-23. `verified live` = opened in full via browser; `index` = search-result text from the official page.

- Elastic Security ECS field reference — https://www.elastic.co/docs/reference/security/fields-and-object-schemas/siem-field-reference — verified live — required fields, auth/network/host/alert field sets.
- ECS Event Fields (ECS Reference 1.10) — https://www.elastic.co/guide/en/ecs/1.10/ecs-event.html — verified live — event.action/category/type/outcome/kind/id/original/created/ingested/severity/duration definitions, types, closed value lists.
- ECS fields list incl. threat.* (Packetbeat Reference 7.11) — https://www.elastic.co/guide/en/beats/packetbeat/7.11/exported-fields-ecs.html — index — @timestamp type/example, threat.framework/tactic.id/technique.id, event.ingested ordering.
- ECS Rule Fields — https://www.elastic.co/guide/en/ecs/8.14/ecs-rule.html — index — rule.id/name/description/category.
- OCSF Authentication class [3002] v1.9.0 — https://schema.ocsf.io/1.9.0/classes/authentication?extensions= — verified live — category_uid 3, class_uid 3002, activity_id values, dst_endpoint, actor, raw_data, message, metadata, observables, severity_id.
- OCSF severity/status enums (class pages, v1.9.0) — https://schema.ocsf.io/1.9.0/classes/file_remediation_activity?extensions= — index — severity_id 0–6/99 with captions, status_id success/failure semantics. Finding status (New/In Progress/Suppressed/Resolved) via OCSF Detection Finding definitions in search results.
- Wazuh Rules Classification — https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html — verified live — rule.level 0–16 table, alert threshold note.
- Wazuh: Detect an SSH brute-force attack (alert JSON anatomy) — https://documentation.wazuh.com/4.0/learning-wazuh/ssh-brute-force.html — verified live — full alerts.json record (rule/agent/manager/decoder/data/full_log/location), composite rule 5712.
- Wazuh global config (logall/archives) — https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/global.html — index — logall/logall_json default no, archives paths; alerts-only default model.
- Wazuh MITRE ATT&CK integration — https://documentation.wazuh.com/4.4/user-manual/ruleset/mitre.html — index — alert-to-MITRE mapping module.
- Splunk CIM Authentication — https://help.splunk.com/en/splunk-enterprise-security-7/common-information-model/8.8/data-models/authentication — verified live — action/app/src/dest/user/src_user/signature/signature_id fields and prescribed values.
- Splunk CIM Network Traffic — https://help.splunk.com/en/splunk-enterprise-security-8/common-information-model/8.8/data-models/network-traffic — verified live — All_Traffic fields: action/app/bytes*/dest*/src*/transport/protocol/duration/dvc/flow_id/rule/session_id/tcp_flag/ttl.
- Zeek conn.log (Book of Zeek) — https://docs.zeek.org/en/master/reference/logs/conn.html — verified live — full conn.log JSON records, uid/duration/bytes/conn_state/history semantics.
- Working notes with per-source extracts: `notes/sources.md` in this research directory.
