//! On-demand inspection. HTTP, DNS, ICMP and database access use Rust libraries.
use crate::Result;
use hickory_resolver::{TokioResolver, config::LookupIpStrategy};
use reqwest::{Client, redirect::Policy};
use serde_json::Value;
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::Ordering,
        mpsc::{Receiver, Sender},
    },
    time::{Duration, Instant},
};
use url::Url;

pub use browser_relay::Cancel;
pub use browser_relay::certificate::{CertificateInfo, certificate_info};
pub use browser_relay::geo::Location;
#[cfg(test)]
use browser_relay::route::next_redirect;
use browser_relay::route::{Next, ResponseError, Route};

pub const PROBE_COUNT: usize = 8;

pub enum Event {
    Dns(String, Vec<IpAddr>),
    Connection {
        url: String,
        secure: bool,
        status: u16,
        elapsed_ms: f64,
        peer: Option<IpAddr>,
        certificate: Option<Result<CertificateInfo>>,
    },
    Assessment {
        encrypted: bool,
        complete: bool,
    },
    Location(IpAddr, Result<Location>),
    Probe(IpAddr, Option<f64>),
    PingUnavailable(IpAddr, String),
    Section(String, String),
    Peer(IpAddr),
    PublicHost(String),
    Redirect(String),
    Resumed,
    Insights(crate::reputation::Report, Vec<String>),
    Done,
}

pub use browser_relay::link::{host, public_ip, public_name, reputation_url, target};

// Use the same current Rust resolver for HTTP and direct DNS checks. Reqwest's
// optional built-in adapter still pins an older Hickory release.
struct SystemResolver;
impl reqwest::dns::Resolve for SystemResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let ips = addresses(name.as_str())
                .await
                .map_err(std::io::Error::other)?;
            let addresses = ips.into_iter().map(|ip| SocketAddr::new(ip, 0));
            Ok(Box::new(addresses) as reqwest::dns::Addrs)
        })
    }
}
pub(crate) fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .dns_resolver(Arc::new(SystemResolver))
        .redirect(Policy::none())
        .referer(false)
        .tls_info(true)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .user_agent("BrowserRelay/0.2")
}

// Dropping the future cancels requests, DNS, ping, and their Tokio tasks. No
// long-lived network runtime or DNS cache is retained after the popup closes.
pub(crate) fn run_async<T>(cancel: &Cancel, future: impl Future<Output = Result<T>>) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        tokio::select! {
            biased;
            _ = async { loop {
                if cancel.load(Ordering::Relaxed) { break; }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }} => Err("Cancelled".into()),
            result = future => result,
        }
    })
}

fn section(sender: &Sender<Event>, title: &str, detail: impl Into<String>) {
    let _ = sender.send(Event::Section(title.into(), detail.into()));
}

#[cfg(test)]
pub fn run(link: &str, sender: &Sender<Event>, cancel: &Cancel) {
    run_with_redirects(link, sender, cancel, None);
}

pub fn run_with_redirects(
    link: &str,
    sender: &Sender<Event>,
    cancel: &Cancel,
    consent: Option<&Receiver<()>>,
) {
    if let Err(error) = run_async(cancel, inspect(link, sender, consent)) {
        section(sender, "Check stopped", error);
    }
    let _ = sender.send(Event::Done);
}

fn connection_error(error: reqwest::Error, url: &Url) -> String {
    use std::error::Error;
    let category = if error.is_timeout() {
        "Connection timed out"
    } else if error.is_connect() {
        "Could not establish the connection"
    } else {
        "Request failed"
    };
    let error = error.without_url();
    let mut causes = Vec::new();
    let mut source = error.source();
    // Preserve actionable TLS/socket causes without copying URL secrets or
    // control characters into the report. Bound untrusted error text.
    for _ in 0..12 {
        let Some(cause) = source else { break };
        let mut message = cause.to_string().replace(url.as_str(), "[URL]");
        for secret in [Some(url.path()).filter(|p| p.len() > 1), url.query()]
            .into_iter()
            .flatten()
        {
            message = message.replace(secret, "[redacted]");
        }
        let message: String = message
            .chars()
            .filter(|c| !c.is_control())
            .take(500)
            .collect();
        if !message.is_empty() && !causes.contains(&message) {
            causes.push(message);
        }
        source = cause.source();
    }
    format!(
        "{category}\n{}\nCertificate checks were not bypassed.",
        causes.join("\n")
    )
}

pub(crate) async fn addresses(name: &str) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = name.parse() {
        return Ok(vec![ip]);
    }
    let mut builder =
        TokioResolver::builder_tokio().map_err(|e| format!("System DNS configuration: {e}"))?;
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.options_mut().timeout = Duration::from_secs(3);
    builder.options_mut().attempts = 1;
    // Absolute query: avoid disclosing public names to search-suffix domains.
    let resolver = builder
        .build()
        .map_err(|e| format!("DNS resolver configuration: {e}"))?;
    let lookup = tokio::time::timeout(
        Duration::from_secs(6),
        resolver.lookup_ip(format!("{}.", name.trim_end_matches('.'))),
    )
    .await
    .map_err(|_| "DNS lookup timed out.")?
    .map_err(|e| format!("DNS lookup failed: {e}"))?;
    let ips: Vec<_> = lookup.iter().collect();
    if ips.is_empty() {
        Err("No A/AAAA addresses found.".into())
    } else {
        Ok(ips)
    }
}

pub(crate) fn proxy_configured() -> bool {
    [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
}

async fn inspect(link: &str, sender: &Sender<Event>, consent: Option<&Receiver<()>>) -> Result<()> {
    let mut route = Route::new(link)?;
    let proxied = proxy_configured();
    if proxied {
        section(
            sender,
            "Proxy configuration detected",
            "HTTP honors proxy and NO_PROXY settings. Separate DNS and ping checks are skipped so they cannot bypass your proxy. Peer IP and GeoIP may describe the proxy. Hostname-based online lookups are unavailable in this mode.",
        );
    }
    let mut peers = HashSet::new();
    loop {
        let previous_hosts = route.names.len();
        let url = match route.begin_request() {
            Ok(url) => url,
            Err(error) => {
                section(sender, "Check stopped", error);
                break;
            }
        };
        let name = host(&url);
        if route.names.len() != previous_hosts {
            let report = crate::reputation::check(&route.names);
            section(sender, "Local domain insights", report.detail());
            let _ = sender.send(Event::Insights(report, route.names.clone()));
        }
        let ips = if proxied {
            Vec::new()
        } else {
            match addresses(&name).await {
                Ok(ips) => ips,
                Err(e) => {
                    section(sender, "DNS unavailable", e);
                    break;
                }
            }
        };
        if !proxied {
            let _ = sender.send(Event::Dns(name.clone(), ips.clone()));
            section(
                sender,
                &format!("DNS · {name}"),
                ips.iter()
                    .map(|ip| format!("{}  {ip}", if ip.is_ipv4() { "A" } else { "AAAA" }))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
        if route.requests == 1
            && !proxied
            && ips.iter().all(|ip| public_ip(*ip))
            && (public_name(&name) || name.parse::<IpAddr>().is_ok())
        {
            let _ = sender.send(Event::PublicHost(name.clone()));
        }
        if name.split('.').any(|s| s.starts_with("xn--")) {
            section(
                sender,
                "Internationalized hostname",
                format!(
                    "ASCII spelling: {name}\nCheck the spelling carefully; similar-looking letters can belong to different domains."
                ),
            );
        }
        let sockets: Vec<_> = ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, url.port_or_known_default().unwrap()))
            .collect();
        let builder = client_builder();
        let builder = if proxied {
            builder
        } else {
            builder.resolve_to_addrs(&name, &sockets)
        };
        let client = builder.build().map_err(|e| e.to_string())?;
        let started = Instant::now();
        let response = match client.head(url.clone()).send().await {
            Ok(response) => response,
            Err(e) => {
                section(
                    sender,
                    "Connection could not be verified",
                    connection_error(e, &url),
                );
                break;
            }
        };
        let secure = url.scheme() == "https";
        let status = response.status();
        let peer = response.remote_addr().map(|addr| addr.ip());
        if let Some(ip) = peer {
            peers.insert(ip);
        }
        // Read metadata from the already-verified TLS connection: no extra
        // certificate lookup, AIA fetch, or request to a third-party service.
        let certificate = secure.then(|| {
            response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|tls| tls.peer_certificate())
                .ok_or_else(|| {
                    "Certificate details were not provided by this connection.".to_string()
                })
                .and_then(certificate_info)
        });
        if let Some(result) = &certificate {
            section(
                sender,
                &format!("Certificate · {name}"),
                result
                    .as_ref()
                    .map(|info| info.detail.clone())
                    .unwrap_or_else(|e| e.clone()),
            );
        }
        let _ = sender.send(Event::Connection {
            url: url.to_string(),
            secure,
            status: status.as_u16(),
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
            peer,
            certificate,
        });
        let tls = if secure {
            "HTTPS · certificate chain and hostname verified"
        } else {
            "HTTP · connection is not encrypted"
        };
        section(
            sender,
            &format!("Connection {} · {name}", route.requests),
            format!(
                "{tls}\nHTTP {} · {} ms · peer {}\n{url}",
                status.as_u16(),
                started.elapsed().as_millis(),
                peer.map(|ip| ip.to_string())
                    .unwrap_or("unavailable".into())
            ),
        );
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|h| h.to_str().ok());
        match route.response(status.as_u16(), location) {
            Err(error) => {
                section(
                    sender,
                    match &error {
                        ResponseError::Redirect(_) => "Redirect stopped",
                        ResponseError::UnexpectedResponse => "Inspection stopped",
                    },
                    error.to_string(),
                );
                break;
            }
            Ok(Next::Done) => break,
            Ok(Next::Request) => {}
            Ok(Next::Consent(next)) => {
                section(
                    sender,
                    "Redirect to another origin",
                    format!(
                        "{next}\nNot contacted. Continue explicitly below to send a request to this destination."
                    ),
                );
                let _ = sender.send(Event::Assessment {
                    encrypted: route.encrypted,
                    complete: false,
                });
                let _ = sender.send(Event::Redirect(next.to_string()));
                let Some(consent) = consent else { break };
                loop {
                    match consent.try_recv() {
                        Ok(()) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(()),
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            tokio::time::sleep(Duration::from_millis(40)).await
                        }
                    }
                }
                route.allow_redirect()?;
                let _ = sender.send(Event::Resumed);
            }
        }
    }
    let _ = sender.send(Event::Assessment {
        encrypted: route.encrypted,
        complete: route.complete,
    });
    section(
        sender,
        "Connection assessment",
        if route.encrypted && route.complete {
            "All observed connections used verified HTTPS. Site trust is unknown; encryption does not establish that the content is safe."
        } else {
            "The route was incomplete (at most six requests) or included unencrypted HTTP. Site trust is unknown."
        },
    );
    let mut peers: Vec<_> = peers.into_iter().collect();
    peers.sort();
    for ip in peers {
        if public_ip(ip) {
            let _ = sender.send(Event::Peer(ip));
        }
        let location = local_geo(ip);
        section(
            sender,
            &format!("Local GeoIP · {ip}"),
            location
                .as_ref()
                .map(|location| location.detail.clone())
                .unwrap_or_else(|e| e.clone()),
        );
        let _ = sender.send(Event::Location(ip, location));
        if !proxied {
            section(
                sender,
                &format!("Ping · {ip}"),
                ping(ip, sender).await.unwrap_or_else(|e| {
                    let _ = sender.send(Event::PingUnavailable(ip, e.clone()));
                    e
                }),
            );
        } else {
            let _ = sender.send(Event::PingUnavailable(
                ip,
                "Skipped to respect proxy settings".into(),
            ));
        }
    }
    Ok(())
}

async fn ping(ip: IpAddr, sender: &Sender<Event>) -> Result<String> {
    let config = surge_ping::Config::builder()
        .kind(if ip.is_ipv4() {
            surge_ping::ICMP::V4
        } else {
            surge_ping::ICMP::V6
        })
        .build();
    let client = surge_ping::Client::new(&config).map_err(|e| format!("ICMP unavailable: {e}. The OS may restrict ping sockets; no elevated privileges are requested."))?;
    let mut pinger = client.pinger(ip, surge_ping::PingIdentifier(0)).await;
    pinger.timeout(Duration::from_secs(2));
    let mut timings = Vec::new();
    for seq in 0..PROBE_COUNT {
        let result = pinger
            .ping(surge_ping::PingSequence(seq as u16), &[0; 16])
            .await;
        let elapsed = result
            .ok()
            .map(|(_, elapsed)| elapsed.as_secs_f64() * 1000.0);
        let _ = sender.send(Event::Probe(ip, elapsed));
        timings.push(match elapsed {
            Some(ms) => format!("Reply {} · {ms:.1} ms", seq + 1),
            None => format!("Probe {} · no reply", seq + 1),
        });
        if seq + 1 < PROBE_COUNT {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }
    Ok(format!(
        "{}\nICMP may be filtered. Latency and reachability are not trust signals.",
        timings.join("\n")
    ))
}

fn geo_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("BROWSER_RELAY_GEOIP_DB") {
        return Ok(path.into());
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));
    if let Some(data) = data {
        let path = data.join("browser-relay/GeoIP-Country.mmdb");
        if path.is_file() {
            return Ok(path);
        }
    }
    for dir in ["/usr/share/GeoIP", "/var/lib/GeoIP"] {
        for file in [
            "GeoLite2-City.mmdb",
            "GeoIP2-City.mmdb",
            "GeoLite2-Country.mmdb",
            "GeoIP2-Country.mmdb",
            "dbip-country-lite.mmdb",
        ] {
            let path = PathBuf::from(dir).join(file);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    Err("No local MMDB database found. Set BROWSER_RELAY_GEOIP_DB to a GeoLite2/GeoIP2 City or Country .mmdb file. Legacy GeoIP .dat files are not supported. No online fallback was used.".into())
}

fn local_geo(ip: IpAddr) -> Result<Location> {
    browser_relay::geo::lookup(&geo_path()?, ip)
}

async fn json_get(url: Url) -> Result<Value> {
    let client = client_builder()
        .https_only(true)
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "Service returned HTTP {}. Redirects are not followed.",
            response.status()
        ));
    }
    let bytes = crate::http::body(response, 65536, "Service response exceeded 64 KiB.").await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| "The service returned an unreadable response.".into())
}

fn geo_url(ip: IpAddr) -> Result<Url> {
    if !public_ip(ip) {
        return Err("Private/reserved IPs are never sent to online services.".into());
    }
    Url::parse(&format!("https://ipwho.is/{ip}")).map_err(|e| e.to_string())
}
pub fn online_geo(ip: IpAddr, cancel: &Cancel) -> Result<String> {
    let url = geo_url(ip)?;
    run_async(cancel, async {
        let data = json_get(url).await?;
        if data["success"].as_bool() != Some(true) {
            return Err(data["message"]
                .as_str()
                .unwrap_or("Location unavailable.")
                .into());
        }
        let field = |v: &Value| v.as_str().unwrap_or("unknown").to_string();
        Ok(format!(
            "{}, {}, {}\nNetwork: {} · ASN {}\nSource: ipwho.is · approximate location; a CDN/proxy may hide the origin.",
            field(&data["city"]),
            field(&data["region"]),
            field(&data["country"]),
            field(&data["connection"]["org"]),
            data["connection"]["asn"]
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };
    #[test]
    fn reads_subject_and_signing_issuer_from_the_certificate() {
        let info = certificate_info(include_bytes!("../tests/fixtures/certificate.der")).unwrap();
        assert_eq!(info.subject, "Example Service · relay.example");
        assert_eq!(info.issuer, "Example Issuer · Relay Test CA");
        assert!(
            info.detail
                .contains("DNS names: relay.example, alt.example")
        );
        assert!(info.detail.contains("Valid until:"));
        assert!(certificate_info(b"invalid certificate").is_err());
    }

    #[test]
    fn validates_targets_before_any_network_activity() {
        for input in [
            "file:///etc/passwd",
            "ftp://example.com",
            "https://user:secret@example.com",
            "https://-option.com",
            "https://bad_host.com",
        ] {
            assert!(target(input).is_err(), "{input}");
        }
        assert_eq!(
            target("https://example.com/a?b=c#secret").unwrap().as_str(),
            "https://example.com/a?b=c"
        );
        assert_eq!(host(&target("https://[::1]/").unwrap()), "::1");
        assert!(host(&target("https://bücher.de/").unwrap()).starts_with("xn--"));
    }
    #[test]
    fn public_names_include_idn_tlds_but_not_unknown_namespaces() {
        let url = target("https://пример.рф/private?secret=value").unwrap();
        let name = host(&url);
        assert!(public_name(&name));
        assert!(reputation_url(&name).unwrap().ends_with(&name));
        for name in [
            "service.corporate-namespace",
            "name.-com",
            "bad-.com",
            "name.internal",
            "name.onion",
        ] {
            assert!(!public_name(name), "{name}");
        }
    }

    #[test]
    fn external_requests_only_contain_the_disclosed_identifier() {
        let input = target("https://Example.COM/private/account?token=secret#fragment").unwrap();
        let name = host(&input);
        assert_eq!(
            reputation_url(&name).unwrap(),
            "https://www.virustotal.com/gui/domain/example.com"
        );
        assert_eq!(
            geo_url("1.1.1.1".parse().unwrap()).unwrap().as_str(),
            "https://ipwho.is/1.1.1.1"
        );
        for bad in [
            "localhost",
            "printer.local",
            "machine.internal",
            "foo.onion",
            "10.0.0.1",
            "127.0.0.1",
            "example.com/path?secret",
            "evil.com@other.com",
        ] {
            assert!(reputation_url(bad).is_err(), "{bad}");
        }
        for ip in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "2002:7f00:1::1",
        ] {
            assert!(geo_url(ip.parse().unwrap()).is_err(), "{ip}");
        }
    }

    #[test]
    fn redirects_reject_credentials_non_web_schemes_and_downgrades() {
        let current = target("https://example.com/private?token=secret").unwrap();
        for next in [
            "http://example.com/",
            "file:///etc/passwd",
            "https://user:pass@other.com/",
        ] {
            assert!(next_redirect(&current, next).is_err());
        }
        assert_eq!(
            next_redirect(&current, "/next#fragment").unwrap().as_str(),
            "https://example.com/next"
        );
        assert_ne!(
            next_redirect(&current, "https://other.com/")
                .unwrap()
                .origin(),
            current.origin()
        );
    }

    fn server(reply: &str, count: usize) -> (String, thread::JoinHandle<Vec<String>>) {
        server_replies(
            TcpListener::bind("127.0.0.1:0").unwrap(),
            vec![reply.to_string(); count],
        )
    }
    fn server_replies(
        listener: TcpListener,
        replies: Vec<String>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut requests = Vec::new();
            while requests.len() < replies.len() && Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                loop {
                    let mut byte = [0];
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                requests.push(String::from_utf8(request).unwrap());
                stream
                    .write_all(replies[requests.len() - 1].as_bytes())
                    .unwrap();
            }
            requests
        });
        (url, thread)
    }

    #[test]
    fn interim_only_responses_do_not_complete_but_a_following_final_response_does() {
        for (reply, complete) in [
            (
                "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
                false,
            ),
            ("HTTP/1.1 103 Early Hints\r\n\r\n", false),
            (
                "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                true,
            ),
        ] {
            let (url, server) = server(reply, 1);
            let (sender, receiver) = mpsc::channel();
            run(&url, &sender, &Arc::new(AtomicBool::new(false)));
            let events: Vec<_> = receiver.try_iter().collect();
            assert_eq!(
                events
                    .iter()
                    .any(|e| matches!(e, Event::Assessment { complete: true, .. })),
                complete
            );
            assert!(events.iter().any(|e| matches!(
                e,
                Event::Assessment {
                    encrypted: false,
                    ..
                }
            )));
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, Event::Section(title, _) if title == "Redirect stopped"))
            );
            assert_eq!(server.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn nonstandard_http_status_completes_the_inspected_route() {
        let (url, server) = server(
            "HTTP/1.1 999 Blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );
        let (sender, receiver) = mpsc::channel();
        run(&url, &sender, &Arc::new(AtomicBool::new(false)));
        let events: Vec<_> = receiver.try_iter().collect();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Connection { status: 999, .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Assessment { complete: true, .. }))
        );
        assert!(!events.iter().any(|e| matches!(e, Event::Redirect(_))));
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[test]
    fn redirect_back_to_an_earlier_host_updates_domain_insights() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.2:0").unwrap();
        let return_url = format!("http://{}/returned", first.local_addr().unwrap());
        let other_url = format!("http://{}/other", second.local_addr().unwrap());
        let redirect = |url: &str| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        };
        let (start, first_server) = server_replies(
            first,
            vec![
                redirect(&other_url),
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            ],
        );
        let (_, second_server) = server_replies(second, vec![redirect(&return_url)]);
        let (sender, receiver) = mpsc::channel();
        let (consent, decisions) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker =
            thread::spawn(move || run_with_redirects(&start, &sender, &cancel, Some(&decisions)));
        let mut reports = Vec::new();
        loop {
            match receiver.recv_timeout(Duration::from_secs(6)).unwrap() {
                Event::Redirect(_) => consent.send(()).unwrap(),
                Event::Insights(_, names) => reports.push(names),
                Event::Done => break,
                _ => {}
            }
        }
        worker.join().unwrap();
        assert_eq!(
            reports,
            vec![
                vec!["127.0.0.1"],
                vec!["127.0.0.1", "127.0.0.2"],
                vec!["127.0.0.1", "127.0.0.2", "127.0.0.1"]
            ]
        );
        assert_eq!(first_server.join().unwrap().len(), 2);
        assert_eq!(second_server.join().unwrap().len(), 1);
    }

    #[test]
    fn direct_check_does_not_follow_another_origin_or_offer_private_lookups() {
        let (url, server) = server(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/do-not-contact?secret=hidden\r\nSet-Cookie: session=hidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );
        let (sender, receiver) = mpsc::channel();
        run(
            &format!("{url}/private?token=secret#fragment"),
            &sender,
            &Arc::new(AtomicBool::new(false)),
        );
        let events: Vec<_> = receiver.try_iter().collect();
        assert!(events.iter().any(|e| matches!(e, Event::Redirect(_))));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::PublicHost(_) | Event::Peer(_)))
        );
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("HEAD /private?token=secret HTTP/1.1"));
        let headers = requests[0].to_ascii_lowercase();
        for forbidden in ["fragment", "referer:", "cookie:", "authorization:"] {
            assert!(!headers.contains(forbidden));
        }
    }

    #[test]
    fn http_client_never_reuses_response_cookies_or_follows_redirects() {
        let (url, server) = server(
            "HTTP/1.1 302 Found\r\nLocation: /unexpected\r\nSet-Cookie: session=hidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            2,
        );
        let cancel = Arc::new(AtomicBool::new(false));
        run_async(&cancel, async {
            let client = client_builder().no_proxy().build().unwrap();
            for _ in 0..2 {
                assert_eq!(
                    client.head(&url).send().await.unwrap().status().as_u16(),
                    302
                );
            }
            Ok(())
        })
        .unwrap();
        for request in server.join().unwrap() {
            assert!(request.starts_with("HEAD / HTTP/1.1"));
            assert!(!request.to_ascii_lowercase().contains("cookie:"));
        }
    }

    #[test]
    fn redirect_consent_preserves_the_session_and_earlier_connections() {
        let (destination, final_server) = server(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            1,
        );
        let (start, first_server) = server(
            &format!(
                "HTTP/1.1 302 Found\r\nLocation: {destination}/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            1,
        );
        let (sender, receiver) = mpsc::channel();
        let (consent, decisions) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker =
            thread::spawn(move || run_with_redirects(&start, &sender, &cancel, Some(&decisions)));
        let mut connections = 0;
        let mut resumed = false;
        let mut complete = false;
        loop {
            match receiver.recv_timeout(Duration::from_secs(5)).unwrap() {
                Event::Connection { .. } => connections += 1,
                Event::Redirect(_) => {
                    assert_eq!(connections, 1);
                    assert!(
                        receiver.recv_timeout(Duration::from_millis(100)).is_err(),
                        "Must wait for consent"
                    );
                    consent.send(()).unwrap();
                }
                Event::Resumed => resumed = true,
                Event::Assessment {
                    encrypted,
                    complete: finished,
                } => {
                    assert!(
                        !encrypted,
                        "The original HTTP hop must remain in the assessment"
                    );
                    complete |= finished;
                }
                Event::Done => break,
                _ => {}
            }
        }
        worker.join().unwrap();
        assert!(resumed && complete);
        assert_eq!(connections, 2);
        assert_eq!(first_server.join().unwrap().len(), 1);
        assert_eq!(final_server.join().unwrap().len(), 1);
    }

    #[test]
    fn diagnostic_keeps_socket_cause_and_omits_url_secrets() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let url = target(&format!("http://{address}/private-path?secret-token")).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        run_async(&cancel, async {
            let error = client_builder()
                .no_proxy()
                .build()
                .unwrap()
                .head(url.clone())
                .send()
                .await
                .unwrap_err();
            let detail = connection_error(error, &url);
            assert!(
                detail.to_ascii_lowercase().contains("connection refused"),
                "{detail}"
            );
            assert!(!detail.contains("private-path") && !detail.contains("secret-token"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn closing_cancels_in_flight_work() {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            flag.store(true, Ordering::Relaxed);
        });
        let start = Instant::now();
        let result = run_async(&cancel, async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        });
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    #[test]
    #[ignore = "Contacts example.com and ipwho.is; requires a local GeoIP database"]
    fn live_public_inspection() {
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::channel();
        run("https://example.com/", &sender, &cancel);
        let mut verified = false;
        for event in receiver.try_iter() {
            if let Event::Section(title, detail) = event {
                println!("{title}: {detail}");
                verified |= detail.contains("certificate chain and hostname verified");
            }
        }
        assert!(verified);
        println!(
            "Local GeoIP: {}",
            local_geo("1.1.1.1".parse().unwrap()).unwrap().detail
        );
        println!(
            "Online GeoIP: {}",
            online_geo("1.1.1.1".parse().unwrap(), &cancel).unwrap()
        );
    }
}
