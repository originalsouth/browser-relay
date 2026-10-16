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
// A single decoded index and validation scratch fit inside this allowance.
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
            let bytes: Vec<u8> = value["der"]
                .as_array()
                .ok_or("Missing certificate.")?
                .iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or("Invalid certificate byte.".into())
                })
                .collect::<Result<_>>()?;
            let cert = crate::certificate::certificate_info(&bytes)?;
            Ok(json!({"subject":cert.subject,"issuer":cert.issuer,"detail":cert.detail}))
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
