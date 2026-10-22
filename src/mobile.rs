//! Small JSON/C boundary for Swift. Policy and data processing stay in the shared modules.
use crate::{
    Result, cache,
    domain_list::{MAX_LIST, MAX_RANK_CSV, Rankings, Snapshot},
    insights,
    route::{Next, Route},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    ffi::{CString, c_char},
    fs,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
const MAX_REQUEST: usize = 128 * 1024;
const MAX_ROUTES: usize = 32;
const ROUTE_IDLE: Duration = Duration::from_secs(5 * 60);
struct RouteEntry {
    route: Route,
    touched: Instant,
    consent: bool,
}
static ROUTES: OnceLock<Mutex<HashMap<u64, RouteEntry>>> = OnceLock::new();
fn expire_routes(routes: &mut HashMap<u64, RouteEntry>, now: Instant) {
    routes.retain(|_, entry| now.saturating_duration_since(entry.touched) < ROUTE_IDLE);
}
fn reserve_route(routes: &mut HashMap<u64, RouteEntry>) {
    if routes.len() >= MAX_ROUTES {
        // Prefer abandoning an idle consent prompt to interrupting a transfer.
        // At capacity even forgotten in-flight requests must be reclaimable.
        if let Some(id) = routes
            .iter()
            .min_by_key(|(id, entry)| (!entry.consent, entry.touched, **id))
            .map(|(id, _)| *id)
        {
            routes.remove(&id);
        }
    }
}
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
// A decoded index, validation scratch and any derived lookalike index share this allowance.
// Serialize memory-heavy local operations; never retain indexes in the extension.
const INDEX_MEMORY: usize = 32 * 1024 * 1024;
const READ_BUFFER: usize = 64 * 1024;
const MAX_GEO: usize = 16 * 1024 * 1024;
const MAX_METADATA: usize = 65536;
static LOCAL_WORK: Mutex<()> = Mutex::new(());
fn index_budget(size: u64, limit: usize) -> Result<usize> {
    if size > limit as u64 {
        return Err("Index exceeds the mobile lookup memory budget; previous index kept.".into());
    }
    limit
        .checked_sub(READ_BUFFER)
        .ok_or_else(|| "Invalid lookup memory budget.".into())
}
fn publish_index<T>(
    path: PathBuf,
    bytes: Vec<u8>,
    limit: usize,
    decode: impl FnOnce(&[u8], usize) -> Result<T>,
) -> Result<()> {
    // Use exactly the lookup decoder and allowance before the atomic rename.
    // Drop validation storage before writing; updates run in the main app.
    let budget = index_budget(bytes.len() as u64, limit)?;
    drop(decode(&bytes, budget).map_err(|e| format!("{e} Previous index kept."))?);
    cache::write(path, &bytes, &Arc::new(false.into()))
}

fn read_index<T>(
    path: &Path,
    decode: impl FnOnce(BufReader<fs::File>, usize) -> Result<T>,
) -> Result<T> {
    let file =
        fs::File::open(path).map_err(|_| "No readable local index. Update lists in the app.")?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("Expected a regular index file.".into());
    }
    let budget = index_budget(metadata.len(), INDEX_MEMORY)?;
    decode(BufReader::with_capacity(READ_BUFFER, file), budget)
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| format!("Missing {key}."))
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Expected a regular file.".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("File exceeds its size limit.".into());
    }
    Ok(bytes)
}
fn route_value(
    id: u64,
    route: &Route,
    action: &str,
    url: Option<&str>,
    notice: Option<&str>,
) -> Value {
    json!({"id": id, "action": action, "url": url, "notice": notice,
        "names": route.names, "encrypted": route.encrypted, "complete": route.complete, "requests": route.requests})
}
fn decision(id: u64, route: &mut Route, next: Result<Next>) -> Value {
    match next {
        Ok(Next::Request) => match route.begin_request() {
            Ok(url) => route_value(id, route, "request", Some(url.as_str()), None),
            Err(e) => route_value(id, route, "stop", None, Some(&e)),
        },
        Ok(Next::Consent(url)) => route_value(id, route, "consent", Some(url.as_str()), None),
        Ok(Next::Done) => route_value(id, route, "done", None, None),
        Err(e) => route_value(id, route, "stop", None, Some(&e)),
    }
}
fn local_insights(root: &Path, names: &[String]) -> Value {
    let _memory = crate::recover_lock(&LOCAL_WORK);
    // Each match arm drops its decoded database before the next one loads.
    let oisd = match read_index(&root.join("oisd.bin"), Snapshot::read_bounded) {
        Ok(db) => {
            let r = insights::oisd_report(&db, names, cache::now());
            json!({"summary":r.summary,"detail":r.detail,"big":r.big,"nsfw":r.nsfw,"stale":r.stale})
        }
        Err(e) => json!({"detail":e}),
    };
    let tranco = match read_index(&root.join("tranco.bin"), Rankings::read_bounded) {
        Ok(db) => {
            let r = insights::rank_report(&db, names, cache::now());
            json!({"rank":r.rank,"position":r.position,"color":r.position.map(insights::popularity_rgb),"caption":r.caption,"detail":r.detail,"available":r.available,"stale":r.stale})
        }
        Err(e) => json!({"detail":e}),
    };
    json!({"oisd":oisd,"tranco":tranco})
}
#[derive(Default)]
struct RiskCache {
    stamp: Option<(PathBuf, u64, u64, std::time::SystemTime)>,
    names: Vec<String>,
    factors: Vec<crate::risk::Factor>,
    available: bool,
    error: Option<String>,
    #[cfg(test)]
    loads: usize,
}
static RISK_CACHE: Mutex<RiskCache> = Mutex::new(RiskCache {
    stamp: None,
    names: Vec::new(),
    factors: Vec::new(),
    available: false,
    error: None,
    #[cfg(test)]
    loads: 0,
});
fn cached_lookalikes(
    root: &Path,
    facts: &crate::risk::Facts,
    cached: &mut RiskCache,
) -> (Vec<crate::risk::Factor>, bool, Option<String>) {
    use std::os::unix::fs::MetadataExt;
    let path = root.join("tranco.bin");
    let stamp = fs::metadata(&path)
        .ok()
        .and_then(|m| Some((path.clone(), m.ino(), m.len(), m.modified().ok()?)));
    let mut names: Vec<_> = std::iter::once(&facts.link)
        .chain(facts.hops.iter().map(|h| &h.url))
        .map(crate::link::host)
        .collect();
    names.sort_unstable();
    names.dedup();
    if cached.stamp != stamp || cached.names != names {
        #[cfg(test)]
        {
            cached.loads += 1;
        }
        let result = read_index(&path, Rankings::read_bounded).and_then(|db| {
            let brands = crate::lookalike::BrandIndex::build_bounded(
                &db,
                INDEX_MEMORY.saturating_sub(db.storage_bytes()),
            )?;
            Ok(crate::risk::lookalikes(
                &names,
                &crate::risk::Context {
                    rankings: &db,
                    brands: &brands,
                },
            ))
        });
        cached.available = result.is_ok();
        cached.error = result.as_ref().err().cloned();
        cached.factors = result.unwrap_or_default();
        cached.names = names;
        cached.stamp = stamp;
    }
    (
        cached.factors.clone(),
        cached.available,
        cached.error.clone(),
    )
}
fn local_risk(root: &Path, facts: &crate::risk::Facts, finished: bool, complete: bool) -> Value {
    use crate::risk::{assess, detail, differing_span, summary};
    let _memory = crate::recover_lock(&LOCAL_WORK);
    let now = i64::try_from(cache::now()).unwrap_or(i64::MAX);
    let (host_factors, lookalikes, unavailable) =
        cached_lookalikes(root, facts, &mut crate::recover_lock(&RISK_CACHE));
    let mut factors = assess(facts, None, now);
    factors.extend(host_factors);
    let factors = crate::risk::ordered(factors);
    let list: Vec<_> = factors
        .iter()
        .map(|f| {
            let compare = f.compare.as_ref().map(|(shown, brand)| {
                let (prefix, suffix) = differing_span(shown, brand);
                json!({"shown":shown,"brand":brand,"shownSpan":[prefix,suffix],"brandSpan":[prefix,suffix]})
            });
            json!({"id":f.id,"severity":f.severity.label(),"word":f.severity.word(),"title":f.title,"evidence":f.evidence,"compare":compare})
        })
        .collect();
    let (text, highest) = summary(&factors, finished, complete);
    json!({"factors":list,"summary":text,"highest":highest.map(|s| s.label()),"lookalikes":lookalikes,"unavailable":unavailable,"detail":detail(&factors)})
}
fn request(value: &Value) -> Result<Value> {
    match string(value, "op")? {
        "validate" => {
            let input = string(value, "url")?;
            let inspection = crate::link::target(input)?;
            let original = url::Url::parse(input).map_err(|e| e.to_string())?;
            Ok(
                json!({"url":original.as_str(),"inspectionURL":inspection.as_str(),"host":crate::link::host(&inspection)}),
            )
        }
        "qr" => {
            let code = crate::qr::encode(string(value, "url")?)
                .ok_or("Link too long for the compact QR code. Copy it instead.")?;
            let modules: Vec<bool> = (0..code.width())
                .flat_map(|y| (0..code.width()).map(move |x| (x, y)))
                .map(|(x, y)| code[(x, y)] == qrcode::Color::Dark)
                .collect();
            Ok(json!({"width":code.width(),"quietZone":crate::qr::QUIET_ZONE,"modules":modules}))
        }
        "certificate" => {
            use base64::{Engine, engine::general_purpose::STANDARD};
            let decode = |key: &str| -> Result<Vec<u8>> {
                let value = string(value, key)?;
                if value.len() > crate::transparency::MAX_CERT * 4 / 3 + 4 {
                    return Err("Certificate exceeds 32 KiB.".into());
                }
                let bytes = STANDARD
                    .decode(value)
                    .map_err(|_| "Invalid certificate encoding.")?;
                if bytes.len() > crate::transparency::MAX_CERT {
                    return Err("Certificate exceeds 32 KiB.".into());
                }
                Ok(bytes)
            };
            let bytes = if value["derBase64"].is_string() {
                decode("derBase64")?
            } else {
                let items = value["der"]
                    .as_array()
                    .filter(|v| v.len() <= crate::transparency::MAX_CERT)
                    .ok_or("Missing or oversized certificate.")?;
                items
                    .iter()
                    .map(|v| {
                        v.as_u64()
                            .and_then(|n| u8::try_from(n).ok())
                            .ok_or("Invalid certificate byte.".into())
                    })
                    .collect::<Result<Vec<_>>>()?
            };
            let issuer = if value["issuerBase64"].is_string() {
                Some(decode("issuerBase64")?)
            } else {
                None
            };
            let path = value["directory"]
                .as_str()
                .map(|dir| Path::new(dir).join(crate::ct_logs::FILE));
            let cert = crate::certificate::certificate_with_ct(
                &bytes,
                issuer.as_deref(),
                path.as_deref(),
            )?;
            Ok(
                json!({"subject":cert.subject,"issuer":cert.issuer,"detail":cert.detail,
                "notBefore":cert.not_before,"notAfter":cert.not_after,
                "ctSummary":cert.transparency.summary,"ctDetail":cert.transparency.detail,"proof":cert.transparency.proof.as_ref().map(|p|p.data())}),
            )
        }
        "proof_prepare" | "proof_audit" | "proof_result" => {
            let path = value["directory"]
                .as_str()
                .map(|dir| Path::new(dir).join(crate::ct_logs::FILE));
            let proof = crate::ct_proof::Proof::from_data(&value["proof"], path.as_deref())?;
            if value["op"] == "proof_prepare" {
                return Ok(
                    json!({"headURL":proof.head_url()?.as_str(),"disclosure":proof.disclosure(),"limit":crate::ct_proof::MAX_RESPONSE}),
                );
            }
            let head = read(
                Path::new(string(value, "head")?),
                crate::ct_proof::MAX_RESPONSE,
            )?;
            let now = crate::cache::now() as i64;
            if value["op"] == "proof_audit" {
                return Ok(json!({"url":proof.audit_url(&head, now)?.as_str()}));
            }
            let audit = read(
                Path::new(string(value, "audit")?),
                crate::ct_proof::MAX_RESPONSE,
            )?;
            Ok(json!({"message":proof.verify(&head, &audit, now)?}))
        }
        "ct_sources" => Ok(
            json!({"list":crate::ct_logs::LIST_URL,"signature":crate::ct_logs::SIGNATURE_URL,
            "listLimit":crate::ct_logs::MAX_LIST,"signatureLimit":crate::ct_logs::MAX_SIGNATURE,"disclosure":crate::ct_logs::DISCLOSURE}),
        ),
        "ct_update" => {
            let bytes = read(Path::new(string(value, "list")?), crate::ct_logs::MAX_LIST)?;
            let sig = read(
                Path::new(string(value, "signature")?),
                crate::ct_logs::MAX_SIGNATURE,
            )?;
            let message = crate::ct_logs::update(
                &Path::new(string(value, "directory")?).join(crate::ct_logs::FILE),
                &bytes,
                &sig,
                &Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )?;
            Ok(json!({"message":message}))
        }
        "history_auth" => {
            crate::certificate_history::validate_key(string(value, "key")?)?;
            Ok(json!({}))
        }
        "history_prepare" => {
            let lookup = crate::certificate_history::prepare(string(value, "host")?)?;
            let url = crate::certificate_history::page_url(&lookup, value["after"].as_str())?;
            Ok(
                json!({"host":lookup.host,"url":url.as_str(),"disclosure":lookup.disclosure,
                "authDisclosure":crate::certificate_history::AUTH_DISCLOSURE,"limit":crate::certificate_history::MAX_RESPONSE}),
            )
        }
        "history_result" => {
            let status = value["status"]
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or("Missing HTTP status.")?;
            crate::certificate_history::status_error(status)?;
            let lookup = crate::certificate_history::prepare(string(value, "host")?)?;
            let bytes = read(
                Path::new(string(value, "path")?),
                crate::certificate_history::MAX_RESPONSE,
            )?;
            let page = crate::certificate_history::page(&bytes, &lookup, value["after"].as_str())?;
            Ok(json!({"message":page.summary,"next":page.next}))
        }
        "route_start" => {
            let mut route = Route::new(string(value, "url")?)?;
            let url = route.begin_request()?;
            let mut routes = crate::recover_lock(ROUTES.get_or_init(Default::default));
            let now = Instant::now();
            expire_routes(&mut routes, now);
            reserve_route(&mut routes);
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let result = route_value(id, &route, "request", Some(url.as_str()), None);
            routes.insert(
                id,
                RouteEntry {
                    route,
                    touched: now,
                    consent: false,
                },
            );
            Ok(result)
        }
        "route_response" | "route_continue" | "route_release" => {
            let id = value["id"].as_u64().ok_or("Missing inspection ID.")?;
            let mut routes = crate::recover_lock(ROUTES.get_or_init(Default::default));
            if value["op"] == "route_release" {
                routes.remove(&id);
                return Ok(json!({}));
            }
            let now = Instant::now();
            expire_routes(&mut routes, now);
            let mut route = routes
                .remove(&id)
                .ok_or("Inspection expired. Start a new inspection.")?
                .route;
            let next = if value["op"] == "route_continue" {
                route.allow_redirect().map(|_| Next::Request)
            } else {
                let status = value["status"]
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
                    .ok_or("Invalid status.")?;
                route
                    .response(status, value["location"].as_str())
                    .map_err(|e| e.to_string())
            };
            let result = decision(id, &mut route, next);
            // Only a pending request or consent needs a live handle. Errors and
            // terminal decisions release it even if the client forgets to do so.
            if matches!(result["action"].as_str(), Some("request" | "consent")) {
                routes.insert(
                    id,
                    RouteEntry {
                        route,
                        touched: now,
                        consent: result["action"] == "consent",
                    },
                );
            }
            Ok(result)
        }
        "insights" => {
            let values = value["names"]
                .as_array()
                .ok_or("Missing inspected hosts.")?;
            if values.len() > 128 {
                return Err("Too many inspected hosts; maximum 128.".into());
            }
            let names = values
                .iter()
                .map(|value| {
                    let name = value.as_str().ok_or("Invalid inspected hostname.")?;
                    if name.len() > 253 {
                        return Err("Inspected hostname exceeds 253 bytes.".into());
                    }
                    Ok(name.to_owned())
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(local_insights(
                Path::new(string(value, "directory")?),
                &names,
            ))
        }
        "risk" => {
            use crate::risk::{Facts, Hop, Validity};
            let hops = value["hops"].as_array().ok_or("Missing hops.")?;
            if hops.len() > crate::route::MAX_HOPS {
                return Err("Too many hops.".into());
            }
            let mut facts = Facts::new(crate::link::target(string(value, "link")?)?);
            for hop in hops {
                facts.hops.push(Hop {
                    url: crate::link::target(string(hop, "url")?)?,
                    status: if hop["status"].is_null() {
                        None
                    } else {
                        Some(
                            hop["status"]
                                .as_u64()
                                .and_then(|s| u16::try_from(s).ok())
                                .filter(|s| (100..=999).contains(s))
                                .ok_or("Invalid status.")?,
                        )
                    },
                    validity: match (hop["notBefore"].as_i64(), hop["notAfter"].as_i64()) {
                        (Some(not_before), Some(not_after)) => Some(Validity {
                            not_before,
                            not_after,
                        }),
                        _ => None,
                    },
                });
            }
            let finished = value["finished"].as_bool().unwrap_or(false);
            let complete = value["complete"].as_bool().unwrap_or(false);
            Ok(local_risk(
                Path::new(string(value, "directory")?),
                &facts,
                finished,
                complete,
            ))
        }
        "validate_geo" => {
            let _memory = crate::recover_lock(&LOCAL_WORK);
            let bytes = read(Path::new(string(value, "path")?), MAX_GEO)?;
            maxminddb::Reader::from_source(bytes)
                .map_err(|e| format!("Invalid MMDB database: {e}"))?;
            Ok(json!({"message":"Local GeoIP database imported."}))
        }
        "geo" => {
            let _memory = crate::recover_lock(&LOCAL_WORK);
            let ip = string(value, "ip")?.parse().map_err(|_| "Invalid IP.")?;
            let path = PathBuf::from(string(value, "path")?);
            if fs::metadata(&path)
                .map_err(|_| "No local GeoIP database imported.")?
                .len()
                > MAX_GEO as u64
            {
                return Err("Use an MMDB database under 16 MiB on mobile.".into());
            }
            let location = crate::geo::lookup(&path, ip)?;
            Ok(
                json!({"name":location.name,"countryCode":location.country_code,"detail":location.detail}),
            )
        }
        "list_sources" => Ok(
            json!({"big":insights::OISD_SOURCES[0],"adult":insights::OISD_SOURCES[1],"metadata":insights::TRANCO_METADATA,
                "limits":{"oisd":MAX_LIST,"tranco":MAX_RANK_CSV,"metadata":MAX_METADATA,"geo":MAX_GEO,"indexMemory":INDEX_MEMORY}}),
        ),
        "tranco_metadata" => {
            let source =
                insights::tranco_metadata(&read(Path::new(string(value, "path")?), MAX_METADATA)?)?;
            Ok(json!({"url":source.url(),"date":source.date(),"id":source.id()}))
        }
        "update_oisd" => {
            let _memory = crate::recover_lock(&LOCAL_WORK);
            let encoded = {
                let db = insights::parse_oisd(
                    &read(Path::new(string(value, "big")?), MAX_LIST)?,
                    &read(Path::new(string(value, "adult")?), MAX_LIST)?,
                    cache::now(),
                )?;
                db.encode()
            };
            publish_index(
                Path::new(string(value, "directory")?).join("oisd.bin"),
                encoded,
                INDEX_MEMORY,
                |bytes, budget| Snapshot::read_bounded(bytes, budget),
            )?;
            Ok(json!({"message":"OISD lists updated."}))
        }
        "update_tranco" => {
            let _memory = crate::recover_lock(&LOCAL_WORK);
            let source = insights::TrancoSource::new(
                string(value, "listID")?,
                string(value, "sourceDate")?,
            )?;
            let encoded = {
                let bytes = read(Path::new(string(value, "path")?), MAX_RANK_CSV)?;
                insights::parse_tranco(&source, &bytes, cache::now())?.encode()
            };
            publish_index(
                Path::new(string(value, "directory")?).join("tranco.bin"),
                encoded,
                INDEX_MEMORY,
                |bytes, budget| Rankings::read_bounded(bytes, budget),
            )?;
            Ok(json!({"message":"Tranco index updated."}))
        }
        _ => Err("Unknown core operation.".into()),
    }
}
fn dispatch(bytes: &[u8]) -> Value {
    let result = serde_json::from_slice(bytes)
        .map_err(|_| "Invalid JSON request.".into())
        .and_then(|v| request(&v));
    match result {
        Ok(data) => json!({"ok":true,"data":data}),
        Err(error) => json!({"ok":false,"error":error}),
    }
}
/// Returns owned UTF-8 JSON. Release it exactly once with `relay_core_free`.
/// # Safety
/// `bytes` must point to `length` readable bytes for this call, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn relay_core_request(bytes: *const u8, length: usize) -> *mut c_char {
    let value = if bytes.is_null() || length > MAX_REQUEST {
        json!({"ok":false,"error":"Invalid or oversized core request."})
    } else {
        std::panic::catch_unwind(|| dispatch(unsafe { std::slice::from_raw_parts(bytes, length) }))
            .unwrap_or_else(|_| json!({"ok":false,"error":"Core operation failed."}))
    };
    CString::new(value.to_string())
        .expect("JSON contains no NUL bytes")
        .into_raw()
}
/// # Safety
/// `value` must be null or an unreleased pointer returned by `relay_core_request`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn relay_core_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    static TEST_STATE: Mutex<()> = Mutex::new(());
    #[test]
    fn over_budget_updates_preserve_the_existing_indexes() {
        let root = std::env::temp_dir().join(format!("relay-mobile-budget-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let snapshot = Snapshot {
            big: crate::domain_list::List::parse("||example.org^").unwrap(),
            nsfw: crate::domain_list::List::parse("||xxx^").unwrap(),
            downloaded: 1,
        };
        let path = root.join("oisd.bin");
        fs::write(&path, snapshot.encode()).unwrap();
        let old = fs::read(&path).unwrap();
        let needed = snapshot.big.storage_bytes() + snapshot.nsfw.storage_bytes();
        assert!(
            publish_index(
                path.clone(),
                snapshot.encode(),
                READ_BUFFER + needed - 1,
                |bytes, budget| Snapshot::read_bounded(bytes, budget)
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), old);
        let ranks = Rankings::parse(
            "1,example.org\n2,example.net",
            "TEST",
            "2026-10-15T00:00:00Z",
            1,
        )
        .unwrap();
        let path = root.join("tranco.bin");
        fs::write(&path, ranks.encode()).unwrap();
        let old = fs::read(&path).unwrap();
        let needed = ranks.storage_bytes() + ranks.source_entries as usize;
        assert!(
            publish_index(
                path.clone(),
                ranks.encode(),
                READ_BUFFER + needed - 1,
                |bytes, budget| Rankings::read_bounded(bytes, budget)
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), old);
        assert!(
            publish_index(
                path.clone(),
                vec![0; READ_BUFFER + 1],
                READ_BUFFER,
                |bytes, budget| Rankings::read_bounded(bytes, budget)
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), old);
        publish_index(
            path.clone(),
            ranks.encode(),
            INDEX_MEMORY,
            |bytes, budget| Rankings::read_bounded(bytes, budget),
        )
        .unwrap();
        assert!(read_index(&path, Rankings::read_bounded).is_ok());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn certificate_bridge_verifies_embedded_scts_and_history_preparation_is_local() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let data = request(&json!({"op":"certificate",
            "derBase64":STANDARD.encode(include_bytes!("../tests/fixtures/ct-github-leaf.der")),
            "issuerBase64":STANDARD.encode(include_bytes!("../tests/fixtures/ct-github-issuer.der"))})).unwrap();
        assert!(
            data["ctSummary"]
                .as_str()
                .unwrap()
                .starts_with("2/2 SCT signatures verified")
        );
        let prepared = request(&json!({"op":"history_prepare","host":"docs.github.com"})).unwrap();
        assert!(
            prepared["disclosure"]
                .as_str()
                .unwrap()
                .contains("docs.github.com")
        );
        assert!(
            prepared["url"]
                .as_str()
                .unwrap()
                .starts_with("https://api.certspotter.com/")
        );
        assert!(request(&json!({"op":"history_prepare","host":"private.local"})).is_err());
    }

    #[test]
    fn mobile_reuses_host_factors_and_invalidates_replaced_lists() {
        let root = std::env::temp_dir().join(format!("relay-risk-reuse-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let first = Rankings::parse("1,paypal.com", "TEST", "date", 0).unwrap();
        fs::write(root.join("tranco.bin"), first.encode()).unwrap();
        let mut cached = RiskCache::default();
        let mut facts =
            crate::risk::Facts::new(crate::link::target("https://paypa1.com/a").unwrap());
        assert_eq!(
            cached_lookalikes(&root, &facts, &mut cached).0[0].id,
            "lookalike"
        );
        for status in [None, Some(200), Some(403)] {
            facts.hops = vec![crate::risk::Hop {
                url: crate::link::target("https://paypa1.com/b").unwrap(),
                status,
                validity: None,
            }];
            assert!(cached_lookalikes(&root, &facts, &mut cached).1);
        }
        assert_eq!(
            cached.loads, 1,
            "same hosts must not reload or rebuild the indexes"
        );
        let next = Rankings::parse("1,microsoft.com", "NEW", "date", 0).unwrap();
        fs::write(root.join("next.bin"), next.encode()).unwrap();
        fs::rename(root.join("next.bin"), root.join("tranco.bin")).unwrap();
        assert!(cached_lookalikes(&root, &facts, &mut cached).0.is_empty());
        assert_eq!(cached.loads, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn risk_op_uses_local_rankings_and_bounds_hops() {
        let root = std::env::temp_dir().join(format!("relay-mobile-risk-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let ranks = Rankings::parse("1,paypal.com", "TEST", "2026-10-15T00:00:00Z", 1).unwrap();
        fs::write(root.join("tranco.bin"), ranks.encode()).unwrap();
        let hop = json!({"url":"https://paypa1.com/","status":200});
        let report = request(&json!({"op":"risk","directory":root,"link":"https://paypa1.com/","hops":[hop],"finished":true,"complete":true})).unwrap();
        assert_eq!(report["factors"][0]["id"], "lookalike");
        assert_eq!(report["factors"][0]["word"], "Warning");
        assert_eq!(report["factors"][0]["compare"]["shownSpan"], json!([5, 4]));
        assert_eq!(report["summary"], "1 warning");
        assert_eq!(report["highest"], "warning");
        assert_eq!(report["lookalikes"], true);
        let attempted = request(
            &json!({"op":"risk","directory":root,"link":"https://example.org/",
            "hops":[{"url":"https://example.org/","status":302},{"url":"https://paypa1.com:8443/"}],
            "finished":true,"complete":false}),
        )
        .unwrap();
        let factors = attempted["factors"].as_array().unwrap();
        assert!(factors.iter().any(|f| f["id"] == "lookalike"));
        assert!(factors.iter().any(|f| f["id"] == "unusual-port"));
        assert!(!factors.iter().any(|f| f["id"] == "refused"));
        assert!(
            attempted["summary"]
                .as_str()
                .unwrap()
                .contains("route incomplete")
        );
        let many = vec![hop; crate::route::MAX_HOPS + 1];
        assert!(
            request(
                &json!({"op":"risk","directory":root,"link":"https://paypa1.com/","hops":many})
            )
            .is_err()
        );
        let empty =
            std::env::temp_dir().join(format!("relay-mobile-risk-empty-{}", std::process::id()));
        fs::create_dir_all(&empty).unwrap();
        let report =
            request(&json!({"op":"risk","directory":empty,"link":"https://paypa1.com/","hops":[]}))
                .unwrap();
        assert_eq!(report["lookalikes"], false);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(empty).unwrap();
    }

    #[test]
    fn insights_keep_early_warnings_and_the_final_host() {
        let root = std::env::temp_dir().join(format!("relay-mobile-hosts-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let snapshot = Snapshot {
            big: crate::domain_list::List::parse("||bad.example^").unwrap(),
            nsfw: crate::domain_list::List::parse("||xxx^").unwrap(),
            downloaded: 1,
        };
        fs::write(root.join("oisd.bin"), snapshot.encode()).unwrap();
        let ranks = Rankings::parse("1,final.example", "TEST", "2026-10-15T00:00:00Z", 1).unwrap();
        fs::write(root.join("tranco.bin"), ranks.encode()).unwrap();
        let names = [
            "bad.example",
            "a.example",
            "b.example",
            "c.example",
            "d.example",
            "e.example",
            "final.example",
        ];
        let report = request(&json!({"op":"insights", "directory":root, "names":names})).unwrap();
        assert_eq!(report["oisd"]["big"], true);
        assert_eq!(report["tranco"]["rank"], 1);
        assert_eq!(report["tranco"]["caption"], "Exact · final.example");
        assert!(
            request(&json!({"op":"insights", "directory":root, "names":vec!["example.org";129]}))
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publisher_limits_come_from_the_enforced_rust_constants() {
        let sources = request(&json!({"op":"list_sources"})).unwrap();
        assert_eq!(
            sources["limits"],
            json!({"oisd":MAX_LIST, "tranco":MAX_RANK_CSV,
            "geo":MAX_GEO, "metadata":MAX_METADATA, "indexMemory":INDEX_MEMORY})
        );
    }

    #[test]
    #[ignore = "Memory probe: set RELAY_INDEX_DIRECTORY to a local OISD/Tranco cache directory"]
    fn local_index_memory_probe() {
        let root = std::env::var_os("RELAY_INDEX_DIRECTORY").unwrap();
        let start = Instant::now();
        for _ in 0..3 {
            let result = local_insights(Path::new(&root), &["github.com".into()]);
            assert!(result["oisd"]["big"].is_boolean(), "{result}");
            assert_eq!(result["tranco"]["available"], true, "{result}");
        }
        eprintln!(
            "Three sequential OISD + Tranco reads: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn abandoned_routes_are_bounded_and_expired_handles_cannot_continue() {
        let _serial = TEST_STATE.lock().unwrap();
        let table = ROUTES.get_or_init(Default::default);
        table.lock().unwrap().clear();
        let active = request(&json!({"op":"route_start", "url":"https://example.org"})).unwrap();
        let mut abandoned = Vec::new();
        for _ in 0..MAX_ROUTES * 3 {
            let first = request(&json!({"op":"route_start", "url":"https://example.org"})).unwrap();
            let consent = request(&json!({"op":"route_response", "id":first["id"], "status":302, "location":"https://example.net"})).unwrap();
            assert_eq!(consent["action"], "consent");
            abandoned.push(first["id"].as_u64().unwrap());
            assert!(table.lock().unwrap().len() <= MAX_ROUTES);
        }
        let id = abandoned[0];
        assert!(request(&json!({"op":"route_continue", "id":id})).is_err());
        request(&json!({"op":"route_release", "id":id})).unwrap();
        // Eviction prefers a consent prompt over the older in-flight transfer.
        assert_eq!(
            request(&json!({"op":"route_response", "id":active["id"], "status":200})).unwrap()["action"],
            "done"
        );
        let id = *abandoned.last().unwrap();
        table.lock().unwrap().get_mut(&id).unwrap().touched = Instant::now() - ROUTE_IDLE;
        assert!(request(&json!({"op":"route_continue", "id":id})).is_err());
        assert!(!table.lock().unwrap().contains_key(&id));
        // Abandoned requests are also reclaimable, without consent or responses.
        let first = request(&json!({"op":"route_start", "url":"https://example.org"})).unwrap();
        for _ in 0..MAX_ROUTES * 2 {
            request(&json!({"op":"route_start", "url":"https://example.org"})).unwrap();
        }
        assert!(request(&json!({"op":"route_response", "id":first["id"], "status":200})).is_err());
        assert_eq!(table.lock().unwrap().len(), MAX_ROUTES);
        for entry in table.lock().unwrap().values_mut() {
            entry.touched = Instant::now() - ROUTE_IDLE;
        }
        let fresh = request(&json!({"op":"route_start", "url":"https://example.org"})).unwrap();
        assert_eq!(table.lock().unwrap().len(), 1);
        request(&json!({"op":"route_release", "id":fresh["id"]})).unwrap();
    }

    #[test]
    fn terminal_routes_release_slots_without_client_cleanup() {
        let _serial = TEST_STATE.lock().unwrap();
        for status in [100, 101, 103, 199, 200, 404, 599, 600, 999, 302, 99, 1000] {
            for _ in 0..40 {
                let first =
                    request(&json!({"op":"route_start","url":"https://example.org"})).unwrap();
                let id = first["id"].as_u64().unwrap();
                let done =
                    request(&json!({"op":"route_response","id":id,"status":status})).unwrap();
                assert_eq!(
                    done["action"],
                    if (200..=999).contains(&status) && status != 302 {
                        "done"
                    } else {
                        "stop"
                    }
                );
                assert!(!ROUTES.get().unwrap().lock().unwrap().contains_key(&id));
                assert!(request(&json!({"op":"route_continue","id":id})).is_err());
                request(&json!({"op":"route_release","id":id})).unwrap();
            }
        }
        let first = request(&json!({"op":"route_start","url":"https://example.org"})).unwrap();
        let id = first["id"].as_u64().unwrap();
        assert!(request(&json!({"op":"route_response","id":id,"status":"bad"})).is_err());
        assert!(!ROUTES.get().unwrap().lock().unwrap().contains_key(&id));
    }

    #[test]
    fn poisoned_routes_are_reset_and_the_bridge_can_start_again() {
        let _serial = TEST_STATE.lock().unwrap();
        let previous = request(&json!({"op":"route_start","url":"https://example.org"})).unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                let _guard = ROUTES.get().unwrap().lock().unwrap();
                panic!("interrupted route mutation");
            })
            .is_err()
        );
        let input = br#"{"op":"route_start","url":"https://example.org"}"#;
        let output = unsafe { relay_core_request(input.as_ptr(), input.len()) };
        let value: Value =
            serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(output) }.to_bytes()).unwrap();
        unsafe {
            relay_core_free(output);
        }
        assert_eq!(value["ok"], true);
        assert!(!ROUTES.get().unwrap().is_poisoned());
        assert!(request(&json!({"op":"route_continue","id":previous["id"]})).is_err());
        request(&json!({"op":"route_release","id":value["data"]["id"]})).unwrap();
    }

    #[test]
    fn bridge_owns_results_and_rejects_bad_requests() {
        let _serial = TEST_STATE.lock().unwrap();
        let input =
            br#"{"op":"validate","url":"https://github.com/originalsouth/browser-relay#readme"}"#;
        let ptr = unsafe { relay_core_request(input.as_ptr(), input.len()) };
        let value: Value =
            serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_bytes()).unwrap();
        unsafe {
            relay_core_free(ptr);
            relay_core_free(std::ptr::null_mut());
        }
        assert_eq!(
            value["data"]["inspectionURL"],
            "https://github.com/originalsouth/browser-relay"
        );
        assert!(value["data"]["url"].as_str().unwrap().ends_with("#readme"));
        assert_eq!(
            dispatch(br#"{"op":"validate","url":"https://user:secret@example.com"}"#)["ok"],
            false
        );
        assert_eq!(dispatch(b"{broken")["ok"], false);
    }
    #[test]
    fn invalid_ffi_inputs_return_owned_errors_without_dereferencing() {
        let _serial = TEST_STATE.lock().unwrap();
        for (pointer, length) in [(std::ptr::null(), 1), (b"x".as_ptr(), MAX_REQUEST + 1)] {
            let output = unsafe { relay_core_request(pointer, length) };
            let value: Value =
                serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(output) }.to_bytes())
                    .unwrap();
            assert_eq!(value["ok"], false);
            unsafe {
                relay_core_free(output);
            }
        }
        assert!(request(&json!({"op":"route_continue","id":0})).is_err());
        assert!(request(&json!({"op":"route_response","id":0,"status":200})).is_err());
    }
    #[test]
    fn mobile_uses_shared_consent_and_budget() {
        let _serial = TEST_STATE.lock().unwrap();
        let value = request(&json!({"op":"route_start","url":"http://example.com/"})).unwrap();
        let id = value["id"].as_u64().unwrap();
        let value = request(
            &json!({"op":"route_response","id":id,"status":302,"location":"https://example.org/"}),
        )
        .unwrap();
        assert_eq!(value["action"], "consent");
        assert_eq!(value["encrypted"], false);
        let value = request(&json!({"op":"route_continue","id":id})).unwrap();
        assert_eq!(value["action"], "request");
        assert_eq!(value["requests"], 2);
        let value = request(&json!({"op":"route_response","id":id,"status":200})).unwrap();
        assert_eq!(value["complete"], true);
        assert_eq!(value["encrypted"], false);
        request(&json!({"op":"route_release","id":id})).unwrap();
    }
}
