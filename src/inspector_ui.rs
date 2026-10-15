use crate::{
    inspect::{self, Cancel, Event, Location, PROBE_COUNT},
    relay::{Action, executable, execute},
};
use gtk::{gdk, glib, prelude::*};
use std::{
    cell::{Cell, RefCell},
    net::IpAddr,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

const PRIVACY: &str = "Inspect sends the path and query to the destination using HEAD requests. Your DNS resolver sees queried hostnames; ping contacts the connected peer. Same-origin redirects are followed. Another origin requires a separate click; HTTPS downgrades are stopped. Fragments and credentials are never sent. No cookies, page scripts, or embedded resources are loaded.\n\nTranco and OISD match cached domain lists locally. Tranco includes subdomains, checks exact names first, and labels parent-only matches. Popularity never overrides a blocklist warning. Big combines ads/tracking and security threats; NSFW is a separate adult/shock list. A match is not a malware verdict, and no match is not proof of safety. Explicit list updates download the full lists without sending inspected hostnames or URLs.\n\nGeoIP uses a local database. Locations are approximate and may describe a CDN or proxy rather than the origin. Proxy settings are respected; separate DNS and ping checks are skipped when a proxy is configured.\n\nOnline GeoIP, VirusTotal and WHOIS / RDAP stay off until explicitly requested. WHOIS sends only the registered domain to the registry shown in the disclosure; a bundled IANA map and public-suffix list choose it locally. Referrals and redirects are never followed. Registration records can be redacted and do not verify the operator. Each lookup shows the exact public hostname or IP it shares. Services see your connection IP and may log the request. Private/reserved destinations are excluded. VirusTotal opens in your browser, where cookies, account identity, and other third parties may apply.\n\nHTTPS validates the connection, not the content. Popularity is not a safety score. ICMP can be blocked; a failed ping does not establish whether a site is safe.";

fn text(value: &str, class: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(value));
    label.set_xalign(0.0);
    label.set_ellipsize(gtk::pango::EllipsizeMode::End);
    label.set_max_width_chars(36);
    label.add_css_class(class);
    label
}
fn wrapped(value: &str) -> gtk::Label {
    let label = text(value, "inspection-detail");
    label.set_ellipsize(gtk::pango::EllipsizeMode::None);
    label.set_wrap(true);
    label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    label.set_max_width_chars(56);
    label
}
fn card(title: &str) -> gtk::Box {
    let panel = gtk::Box::new(gtk::Orientation::Vertical, 6);
    panel.add_css_class("dashboard-card");
    panel.set_hexpand(true);
    panel.append(&text(title, "eyebrow"));
    panel
}
fn popover(content: &impl IsA<gtk::Widget>) -> gtk::Popover {
    let popover = gtk::Popover::new();
    popover.set_position(gtk::PositionType::Top);
    popover.add_css_class("relay");
    popover.add_css_class("inspection-popover");
    popover.set_child(Some(content));
    popover
}
fn menu(caption: &str) -> gtk::MenuButton {
    let button = gtk::MenuButton::builder()
        .label(caption)
        .direction(gtk::ArrowType::Up)
        .build();
    button.add_css_class("dashboard-action");
    button
}
fn assessment_style(encrypted: bool, complete: bool) -> (&'static str, &'static str) {
    match (encrypted, complete) {
        (_, false) => ("Inspection incomplete", "warning-text"),
        (false, true) => ("Route includes HTTP", "warning-text"),
        (true, true) => ("Verified HTTPS", "success"),
    }
}

fn append_log(buffer: &gtk::TextBuffer, title: &str, detail: &str) {
    buffer.insert(&mut buffer.end_iter(), &format!("\n\n{title}\n{detail}"));
}

enum LookupState<T> {
    Running,
    Complete(crate::Result<T>),
}

fn confirmed_task<T, F, U>(
    button: &gtk::MenuButton,
    disclosure: &str,
    action: &str,
    cancel: &Cancel,
    task: F,
    update: U,
) where
    T: Send + 'static,
    F: Fn(&Cancel) -> crate::Result<T> + Send + Sync + 'static,
    U: Fn(LookupState<T>) + 'static,
{
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&text("ONLY IF YOU CHOOSE", "eyebrow"));
    content.append(&wrapped(disclosure));
    content.append(&wrapped("The service sees your connection IP and may log this request. The link's path and query are not shared."));
    let confirm = gtk::Button::with_label(action);
    confirm.add_css_class("route");
    content.append(&confirm);
    let pop = popover(&content);
    button.set_popover(Some(&pop));
    button.set_sensitive(true);
    let weak_pop = pop.downgrade();
    let cancel = cancel.clone();
    let task = Arc::new(task);
    let update = Rc::new(update);
    confirm.connect_clicked(move |confirm| {
        if let Some(pop) = weak_pop.upgrade() {
            pop.popdown();
        }
        confirm.set_sensitive(false);
        update(LookupState::Running);
        let (sender, receiver) = mpsc::channel();
        let task = task.clone();
        let flag = cancel.clone();
        std::thread::spawn(move || {
            let _ = sender.send(task(&flag));
        });
        let update = update.clone();
        let flag = cancel.clone();
        let confirm = confirm.downgrade();
        glib::timeout_add_local(Duration::from_millis(50), move || {
            if flag.load(Ordering::Relaxed) {
                return glib::ControlFlow::Break;
            }
            let result = match receiver.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(_) => Err("Request did not complete".into()),
            };
            update(LookupState::Complete(result));
            if let Some(confirm) = confirm.upgrade() {
                confirm.set_sensitive(true);
            }
            glib::ControlFlow::Break
        });
    });
}

fn online_lookup<F>(
    button: &gtk::MenuButton,
    disclosure: &str,
    output: &gtk::Label,
    log: &gtk::TextBuffer,
    cancel: &Cancel,
    task: F,
) where
    F: Fn(&Cancel) -> crate::Result<String> + Send + Sync + 'static,
{
    let result_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    result_box.set_visible(false);
    result_box.append(&text("LOOKUP RESULT", "eyebrow"));
    let result_buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
    let result_view = gtk::TextView::builder()
        .buffer(&result_buffer)
        .editable(false)
        .cursor_visible(false)
        .wrap_mode(gtk::WrapMode::WordChar)
        .build();
    result_view.add_css_class("inspection-log");
    let result_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(160)
        .child(&result_view)
        .build();
    result_scroll.set_size_request(360, 160);
    result_box.append(&result_scroll);
    let result_weak = result_box.downgrade();
    let button_weak = button.downgrade();
    let output = output.downgrade();
    let log = log.downgrade();
    confirmed_task(
        button,
        disclosure,
        "Run this lookup",
        cancel,
        task,
        move |state| {
            let (Some(output), Some(button), Some(result_box)) = (
                output.upgrade(),
                button_weak.upgrade(),
                result_weak.upgrade(),
            ) else {
                return;
            };
            // A peer change replaces this menu. Even if its old popover remains
            // alive during an animation, its result must not update the new peer.
            if button.popover().and_then(|pop| pop.child()) != result_box.parent() {
                return;
            }
            match state {
                LookupState::Running => output.set_text("Looking up…"),
                LookupState::Complete(result) => {
                    let detail = result.unwrap_or_else(|e| format!("Unavailable: {e}"));
                    output.set_text(detail.lines().next().unwrap_or("No result"));
                    output.set_tooltip_text(Some(&detail));
                    result_buffer.set_text(&detail);
                    result_box.set_visible(true);
                    if let Some(log) = log.upgrade() {
                        append_log(&log, "Optional online lookup", &detail);
                    }
                }
            }
        },
    );
    if let Some(content) = button
        .popover()
        .and_then(|pop| pop.child())
        .and_then(|child| child.downcast::<gtk::Box>().ok())
    {
        content.append(&result_box);
    }
}

#[derive(Clone)]
struct InsightsView {
    rank: gtk::Label,
    rank_caption: gtk::Label,
    big: gtk::Label,
    nsfw: gtk::Label,
    note: gtk::Label,
    row: glib::WeakRef<gtk::Box>,
}
impl InsightsView {
    fn render(&self, combined: &crate::reputation::Report) {
        let rank = &combined.tranco;
        self.rank.set_text(&match rank.rank {
            Some(value) => {
                let digits = value.to_string();
                let mut formatted = String::from("#");
                for (index, c) in digits.chars().enumerate() {
                    if index > 0 && (digits.len() - index).is_multiple_of(3) {
                        formatted.push(',');
                    }
                    formatted.push(c);
                }
                formatted
            }
            None if rank.available => "Unranked".into(),
            None => "Not loaded".into(),
        });
        self.rank_caption.set_text(&rank.caption);
        self.rank.set_tooltip_text(Some(&rank.detail));
        self.rank_caption.set_tooltip_text(Some(&rank.detail));
        let report = &combined.oisd;
        for (label, matched) in [(&self.big, report.big), (&self.nsfw, report.nsfw)] {
            label.set_text(match matched {
                Some(true) => "Listed",
                Some(false) => "No match",
                None => "Unknown",
            });
            for class in ["list-match", "list-neutral", "list-unknown"] {
                label.remove_css_class(class);
            }
            label.add_css_class(match matched {
                Some(true) => "list-match",
                Some(false) => "list-neutral",
                None => "list-unknown",
            });
        }
        self.note.set_text(if report.stale || rank.stale {
            "Stale · update lists"
        } else if report.big.is_none() || !rank.available {
            "Some lists unavailable"
        } else {
            "Checked locally"
        });
        self.note.set_tooltip_text(None);
        if let Some(row) = self.row.upgrade() {
            row.set_tooltip_text(Some(&combined.detail()));
        }
    }
}

fn list_tile(title: &str, caption: &str) -> (gtk::Box, gtk::Label, gtk::Label) {
    let group = gtk::Box::new(gtk::Orientation::Vertical, 2);
    group.add_css_class("insight-tile");
    group.set_hexpand(true);
    group.append(&text(title, "list-kind"));
    let value = text("Checking…", "list-state");
    group.append(&value);
    let caption = text(caption, "list-note");
    group.append(&caption);
    (group, value, caption)
}

fn reputation(button: &gtk::MenuButton, name: &str, status: &gtk::Label) {
    let Ok(url) = inspect::reputation_url(name) else {
        return;
    };
    let browser = if executable(&["chromium", "chromium-browser"]).is_some() {
        Some(Action::Chromium)
    } else if executable(&["firefox", "firefox-esr"]).is_some() {
        Some(Action::Firefox)
    } else {
        None
    };
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&text("VIRUSTOTAL REPORT", "eyebrow"));
    content.append(&wrapped(&format!("Shares {name} with VirusTotal in your browser. The original path and query are not sent. Your browser may share cookies, account identity and other request data. The report describes this initial host, not every redirect.")));
    let confirm = gtk::Button::with_label("Open browser report ↗");
    confirm.add_css_class("route");
    confirm.set_sensitive(browser.is_some());
    content.append(&confirm);
    let pop = popover(&content);
    button.set_popover(Some(&pop));
    button.set_sensitive(true);
    let weak_pop = pop.downgrade();
    let status = status.downgrade();
    confirm.connect_clicked(move |_| {
        if let Some(pop) = weak_pop.upgrade() {
            pop.popdown();
        }
        if let Some(action) = browser {
            let result = execute(action, std::slice::from_ref(&url));
            if let Some(status) = status.upgrade() {
                status.set_text(
                    &result
                        .map(|_| "Opened in browser".into())
                        .unwrap_or_else(|e| e),
                );
            }
        }
    });
}

fn flag(code: &str) -> String {
    let code = code.to_ascii_uppercase();
    if code.len() != 2 || !code.bytes().all(|c| c.is_ascii_uppercase()) {
        return "🌐".into();
    }
    code.bytes()
        .filter_map(|c| char::from_u32(0x1f1e6 + u32::from(c - b'A')))
        .collect()
}

#[derive(Default)]
struct Samples {
    values: Vec<Option<f64>>,
}
impl Samples {
    fn summary(&self) -> (String, String) {
        let replies: Vec<_> = self.values.iter().flatten().copied().collect();
        if self.values.is_empty() {
            return (
                "Waiting…".into(),
                format!("{PROBE_COUNT} probes · latency in milliseconds"),
            );
        }
        let lost = self.values.len() - replies.len();
        let progress = format!(
            "{}/{} probes · {}% loss",
            self.values.len(),
            PROBE_COUNT,
            lost * 100 / self.values.len()
        );
        if replies.is_empty() {
            return ("No replies".into(), progress);
        }
        let average = replies.iter().sum::<f64>() / replies.len() as f64;
        let min = replies.iter().copied().fold(f64::INFINITY, f64::min);
        let max = replies.iter().copied().fold(0.0, f64::max);
        (
            format!("{average:.1} ms"),
            format!("{progress} · {min:.1}–{max:.1} ms"),
        )
    }
}
struct Peer {
    ip: IpAddr,
    location: Option<crate::Result<Location>>,
    samples: Samples,
    ping_error: Option<String>,
}
#[derive(Clone)]
struct PeerView {
    flag: gtk::Label,
    location: gtk::Label,
    note: gtk::Label,
    average: gtk::Label,
    stats: gtk::Label,
    chart: gtk::DrawingArea,
}
impl PeerView {
    fn render(&self, peer: Option<&Peer>, done: bool) {
        let Some(peer) = peer else {
            if done {
                self.location.set_text("Unavailable");
                self.average.set_text("Not measured");
                self.note.set_text("No connected peer available");
                self.stats.set_text("No probes sent");
            }
            return;
        };
        match &peer.location {
            Some(Ok(location)) => {
                self.flag.set_text(&flag(&location.country_code));
                self.location.set_text(&location.name);
                self.location.set_tooltip_text(Some(&location.detail));
                self.note.set_text("Offline GeoIP · approximate location");
                self.note.set_tooltip_text(Some(&location.detail));
            }
            Some(Err(error)) => {
                self.flag.set_text("🌐");
                self.location.set_text("Unknown location");
                self.location.set_tooltip_text(Some(error));
                self.note.set_text(if inspect::public_ip(peer.ip) {
                    "Local data unavailable · see details"
                } else {
                    "Local / reserved address"
                });
                self.note.set_tooltip_text(Some(error));
            }
            None => {
                self.flag.set_text("🌐");
                self.location.set_text("Locating…");
                self.location.set_tooltip_text(None);
                self.note.set_text("Reading the local database");
                self.note.set_tooltip_text(None);
            }
        }
        if let Some(error) = &peer.ping_error {
            self.average.set_text("Not measured");
            self.stats.set_text(error);
            self.stats.set_tooltip_text(Some(error));
        } else {
            let (average, stats) = peer.samples.summary();
            self.average.set_text(&average);
            self.stats.set_text(&stats);
            self.stats.set_tooltip_text(Some(&stats));
        }
        self.chart.queue_draw();
    }
}
fn add_peer(peers: &RefCell<Vec<Peer>>, names: &gtk::StringList, ip: IpAddr) -> usize {
    if let Some(index) = peers.borrow().iter().position(|p| p.ip == ip) {
        return index;
    }
    let index = peers.borrow().len();
    peers.borrow_mut().push(Peer {
        ip,
        location: None,
        samples: Samples::default(),
        ping_error: None,
    });
    names.append(&ip.to_string());
    index
}
fn chart(peers: Rc<RefCell<Vec<Peer>>>, selected: Rc<Cell<usize>>) -> gtk::DrawingArea {
    let area = gtk::DrawingArea::builder()
        .content_height(80)
        .hexpand(true)
        .build();
    area.set_tooltip_text(Some("One bar per ICMP probe. Violet = reply latency; amber × = timeout; gray = pending. Scale adjusts to the highest reply. Exact timings are in Details & privacy."));
    area.set_draw_func(move |_, cr, width, height| {
        let peers = peers.borrow();
        let values = peers
            .get(selected.get())
            .map(|p| p.samples.values.as_slice())
            .unwrap_or(&[]);
        let max = values.iter().flatten().copied().fold(1.0, f64::max);
        let left = 39.0;
        let plot_width = (f64::from(width) - left - 4.0).max(8.0);
        let bottom = f64::from(height) - 17.0;
        let plot_height = (bottom - 8.0).max(1.0);
        cr.set_font_size(9.0);
        for row in 0..3 {
            let fraction = f64::from(row) / 2.0;
            let y = bottom - plot_height * fraction;
            cr.set_source_rgba(0.65, 0.61, 0.75, 0.16);
            cr.set_line_width(1.0);
            cr.move_to(left, y);
            cr.line_to(f64::from(width), y);
            let _ = cr.stroke();
            cr.set_source_rgb(0.61, 0.58, 0.69);
            cr.move_to(0.0, y + 3.0);
            let _ = cr.show_text(&format!("{:.1}", max * fraction));
        }
        let step = plot_width / PROBE_COUNT as f64;
        for index in 0..PROBE_COUNT {
            let x = left + step * index as f64 + step * 0.15;
            let bar_width = step * 0.7;
            match values.get(index) {
                Some(Some(ms)) => {
                    let bar_height = (ms / max * plot_height).max(2.0);
                    let gradient =
                        gtk::cairo::LinearGradient::new(0.0, bottom - bar_height, 0.0, bottom);
                    gradient.add_color_stop_rgb(0.0, 0.76, 0.65, 1.0);
                    gradient.add_color_stop_rgb(1.0, 0.40, 0.28, 0.71);
                    let _ = cr.set_source(&gradient);
                    cr.rectangle(x, bottom - bar_height, bar_width, bar_height);
                    let _ = cr.fill();
                }
                Some(None) => {
                    cr.set_source_rgb(0.94, 0.68, 0.39);
                    cr.set_line_width(2.0);
                    let center = x + bar_width / 2.0;
                    cr.move_to(center - 3.0, bottom - 9.0);
                    cr.line_to(center + 3.0, bottom - 3.0);
                    cr.move_to(center + 3.0, bottom - 9.0);
                    cr.line_to(center - 3.0, bottom - 3.0);
                    let _ = cr.stroke();
                }
                None => {
                    cr.set_source_rgb(0.26, 0.24, 0.32);
                    cr.rectangle(x, bottom - 3.0, bar_width, 3.0);
                    let _ = cr.fill();
                }
            }
            cr.set_source_rgb(0.65, 0.61, 0.73);
            cr.move_to(x + bar_width / 2.0 - 3.0, bottom + 14.0);
            let _ = cr.show_text(&(index + 1).to_string());
        }
    });
    area
}

pub fn show(parent: &gtk::Window, link: &str, multiple: bool) {
    let popup = gtk::Window::builder()
        .title("Inspect link")
        .transient_for(parent)
        .modal(true)
        .destroy_with_parent(true)
        .default_width(800)
        .default_height(720)
        .icon_name("browser-relay")
        .build();
    popup.add_css_class("relay");
    popup.add_css_class("dashboard");
    let header = gtk::HeaderBar::new();
    header.set_decoration_layout(Some(":close"));
    header.set_title_widget(Some(&text("LINK INSPECTION", "brand")));
    popup.set_titlebar(Some(&header));
    let body = gtk::Box::new(gtk::Orientation::Vertical, 10);
    body.set_margin_start(24);
    body.set_margin_end(24);
    body.set_margin_top(10);
    body.set_margin_bottom(8);
    let title_row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let shield = gtk::Image::from_icon_name("security-high-symbolic");
    shield.set_pixel_size(30);
    shield.add_css_class("copy-icon");
    title_row.append(&shield);
    let hostname = inspect::target(link)
        .map(|url| inspect::host(&url))
        .unwrap_or("Link inspection".into());
    let title = text(&hostname, "dashboard-title");
    title.set_hexpand(true);
    title.set_tooltip_text(Some(&hostname));
    title_row.append(&title);
    let spinner = gtk::Spinner::new();
    spinner.start();
    title_row.append(&spinner);
    let status = text("Checking…", "dashboard-badge");
    title_row.append(&status);
    body.append(&title_row);
    let url = text(link, "url");
    url.set_max_width_chars(90);
    url.set_tooltip_text(Some(link));
    body.append(&url);
    let banner = gtk::Revealer::builder()
        .transition_type(gtk::RevealerTransitionType::SlideDown)
        .transition_duration(180)
        .build();
    let warning = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    warning.add_css_class("dashboard-warning");
    let notice = text("", "footer");
    notice.set_hexpand(true);
    warning.append(&notice);
    banner.set_child(Some(&warning));
    body.append(&banner);

    let grid = gtk::Grid::builder()
        .column_spacing(12)
        .row_spacing(12)
        .column_homogeneous(true)
        .build();
    let connection = card("CONNECTION SECURITY");
    let tls = text("Checking…", "dashboard-value");
    connection.append(&tls);
    let response = text("Waiting for destination headers", "inspection-detail");
    connection.append(&response);
    let trust = text("Site trust remains unverified", "footer");
    connection.append(&trust);
    let certificate = gtk::Box::new(gtk::Orientation::Vertical, 3);
    let subject = text("Issued to: waiting for certificate", "url");
    let issuer = text("Signed by: waiting for certificate", "url");
    certificate.append(&subject);
    certificate.append(&issuer);
    connection.append(&certificate);
    grid.attach(&connection, 0, 0, 1, 1);
    let location = card("SERVER LOCATION");
    let location_row = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let flag_label = text("🌐", "country-flag");
    location_row.append(&flag_label);
    let place = text("Locating…", "dashboard-value");
    place.set_hexpand(true);
    location_row.append(&place);
    location.append(&location_row);
    let peers = Rc::new(RefCell::new(Vec::<Peer>::new()));
    let selected = Rc::new(Cell::new(0usize));
    let peer_names = gtk::StringList::new(&[]);
    let selector = gtk::DropDown::new(Some(peer_names.clone()), None::<gtk::Expression>);
    selector.add_css_class("peer-selector");
    selector.set_tooltip_text(Some(
        "Connected peer IP. Selecting a peer updates its location and ping chart.",
    ));
    location.append(&selector);
    let location_note = text("Local database · no online lookup", "footer");
    location.append(&location_note);
    grid.attach(&location, 1, 0, 1, 1);
    let dns = card("DNS & ROUTE");
    let address_count = text("Resolving…", "dashboard-value");
    dns.append(&address_count);
    let addresses = text("Your configured DNS resolver", "dashboard-addresses");
    addresses.set_lines(3);
    addresses.set_wrap(true);
    addresses.set_selectable(true);
    addresses.set_vexpand(true);
    addresses.set_valign(gtk::Align::Start);
    dns.append(&addresses);
    let dns_note = text("A + AAAA · IPv4 and IPv6", "footer");
    dns.append(&dns_note);
    grid.attach(&dns, 0, 1, 1, 1);
    let ping = card("PING · ROUND-TRIP LATENCY");
    let average = text("Waiting…", "dashboard-value");
    ping.append(&average);
    let bars = chart(peers.clone(), selected.clone());
    ping.append(&bars);
    let stats = text("8 probes · milliseconds", "footer");
    ping.append(&stats);
    grid.attach(&ping, 1, 1, 1, 1);
    body.append(&grid);

    let cancel: Cancel = Arc::new(AtomicBool::new(false));
    let log = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
    log.set_text(PRIVACY);
    let online = gtk::Box::new(gtk::Orientation::Vertical, 4);
    online.add_css_class("dashboard-card");
    online.add_css_class("domain-insights");
    let heading = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let title = text("DOMAIN INSIGHTS", "eyebrow");
    title.set_hexpand(true);
    heading.append(&title);
    let list_note = text("On-device indexes", "list-note");
    heading.append(&list_note);
    let update_lists = gtk::MenuButton::builder()
        .icon_name("view-refresh-symbolic")
        .direction(gtk::ArrowType::Up)
        .build();
    update_lists.add_css_class("list-refresh");
    update_lists.set_tooltip_text(Some("Update Tranco + OISD · review download privacy first"));
    heading.append(&update_lists);
    online.append(&heading);
    let list_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    list_row.set_homogeneous(true);
    let (rank_tile, rank_state, rank_caption) =
        list_tile("TRANCO · POPULARITY", "Includes subdomains");
    rank_tile.add_css_class("popularity-tile");
    let (big_tile, big_state, _) = list_tile("OISD · MIXED LIST", "Ads, tracking & threats");
    let (nsfw_tile, nsfw_state, _) = list_tile("OISD · ADULT CONTENT", "Adult & shock content");
    list_row.append(&rank_tile);
    list_row.append(&big_tile);
    list_row.append(&nsfw_tile);
    online.append(&list_row);
    let online_grid = gtk::Grid::builder()
        .column_spacing(8)
        .row_spacing(2)
        .column_homogeneous(true)
        .build();
    let whois = menu("WHOIS / RDAP");
    let whois_result = text("Opt-in · registration", "list-note");
    let reputation_button = menu("VirusTotal ↗");
    let geo = menu("Online GeoIP");
    let reputation_result = text("Opt-in · reputation", "list-note");
    let geo_result = text("Opt-in · city & network", "list-note");
    for (column, (button, result)) in [
        (&whois, &whois_result),
        (&reputation_button, &reputation_result),
        (&geo, &geo_result),
    ]
    .into_iter()
    .enumerate()
    {
        button.set_sensitive(false);
        button.set_hexpand(true);
        button.add_css_class("insight-action");
        button.set_tooltip_text(Some(
            "Opt-in only. Available after a public destination is identified; domain checks are disabled for proxy/private destinations. Click to review what is shared.",
        ));
        online_grid.attach(button, column as i32, 0, 1, 1);
        online_grid.attach(result, column as i32, 1, 1, 1);
    }
    rank_tile.set_tooltip_text(Some("Popularity is not trust. Tranco is not a whitelist and never overrides OISD warnings. Hover over the rank for its source and matching hostname."));
    let insights_view = InsightsView {
        rank: rank_state,
        rank_caption,
        big: big_state,
        nsfw: nsfw_state,
        note: list_note,
        row: list_row.downgrade(),
    };
    let checked_hosts = Arc::new(std::sync::Mutex::new(vec![hostname.clone()]));
    let hosts = checked_hosts.clone();
    let view = insights_view.clone();
    let log_copy = log.downgrade();
    let displayed_hosts = checked_hosts.clone();
    confirmed_task(
        &update_lists,
        "Download Tranco’s top million including subdomains from tranco-list.eu, plus OISD Big and NSFW from big.oisd.nl and nsfw.oisd.nl? These fixed downloads share your connection IP, but never the inspected hostname or URL. Lists stay on this device; updates are manual.",
        "Download lists",
        &cancel,
        move |cancel| {
            let (message, failed) = crate::reputation::update(cancel);
            // Copy the short route before loading indexes; GTK never waits for
            // cache validation while acquiring this shared mutex.
            let names = hosts.lock().unwrap().clone();
            Ok((crate::reputation::check(&names), names, message, failed))
        },
        move |state| match state {
            LookupState::Running => view.note.set_text("Updating…"),
            LookupState::Complete(result) => {
                let detail = match result {
                    Ok((report, names, message, failed)) => {
                        // A redirect may have changed the dashboard while the
                        // update finished. Never replace it with an earlier host.
                        if *displayed_hosts.lock().unwrap() == names {
                            view.render(&report);
                        } else {
                            view.note.set_text("Lists updated · route changed");
                            view.note.set_tooltip_text(Some("The route changed during this update. This report keeps its own source dates; reopen inspection to use the updated lists throughout."));
                        }
                        if failed {
                            view.note.set_text("Update incomplete");
                            view.note.set_tooltip_text(Some(&message));
                        }
                        format!("{message}\n\n{}", report.detail())
                    }
                    Err(error) => {
                        view.note.set_text("Update failed");
                        view.note.set_tooltip_text(Some(&error));
                        error
                    }
                };
                if let Some(log) = log_copy.upgrade() {
                    append_log(&log, "Domain index update", &detail);
                }
            }
        },
    );
    online.append(&online_grid);
    body.append(&online);
    let footer = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let details = menu("Details & privacy");
    let detail_view = gtk::TextView::builder()
        .buffer(&log)
        .editable(false)
        .cursor_visible(false)
        .wrap_mode(gtk::WrapMode::WordChar)
        .build();
    detail_view.add_css_class("inspection-log");
    let detail_scroll = gtk::ScrolledWindow::builder()
        .min_content_width(580)
        .min_content_height(300)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&detail_view)
        .build();
    // With horizontal scrolling disabled, min_content_width alone does not
    // constrain this wrapped TextView inside a popover. Reserve actual space.
    detail_scroll.set_size_request(580, 300);
    details.set_popover(Some(&popover(&detail_scroll)));
    footer.append(&details);
    let scope = text(
        if multiple {
            "First link only · Esc to close"
        } else {
            "Direct checks · Esc to close"
        },
        "footer",
    );
    scope.set_hexpand(true);
    footer.append(&scope);
    let close = gtk::Button::with_label("Back to choices");
    close.add_css_class("route");
    close.add_css_class("compact");
    footer.append(&close);
    body.append(&footer);
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .child(&body)
        .build();
    popup.set_child(Some(&scroll));

    let peer_view = PeerView {
        flag: flag_label,
        location: place,
        note: location_note,
        average,
        stats,
        chart: bars,
    };
    let done = Rc::new(Cell::new(false));
    let view = peer_view.clone();
    let store = peers.clone();
    let selection = selected.clone();
    let finished = done.clone();
    let geo_button = geo.clone();
    let geo_output = geo_result.clone();
    let log_copy = log.clone();
    let flag = cancel.clone();
    selector.connect_selected_notify(move |selector| {
        let index = selector.selected() as usize;
        selection.set(index);
        let store = store.borrow();
        let peer = store.get(index);
        view.render(peer, finished.get());
        geo_button.set_sensitive(false);
        geo_button.set_popover(None::<&gtk::Popover>);
        geo_output.set_text("Unavailable for this peer");
        geo_output.set_tooltip_text(None);
        if let Some(peer) = peer
            && inspect::public_ip(peer.ip)
        {
            let ip = peer.ip;
            geo_output.set_text("Opt-in · city & network");
            online_lookup(
                &geo_button,
                &format!("Send {ip} to ipwho.is for approximate city and network information?"),
                &geo_output,
                &log_copy,
                &flag,
                move |cancel| {
                    inspect::online_geo(ip, cancel).map(|result| format!("{ip} · {result}"))
                },
            );
        }
    });
    let weak_popup = popup.downgrade();
    close.connect_clicked(move |_| {
        if let Some(popup) = weak_popup.upgrade() {
            popup.close();
        }
    });
    let flag = cancel.clone();
    popup.connect_close_request(move |_| {
        flag.store(true, Ordering::Relaxed);
        glib::Propagation::Proceed
    });
    let flag = cancel.clone();
    popup.connect_hide(move |_| {
        flag.store(true, Ordering::Relaxed);
    });
    let keys = gtk::EventControllerKey::new();
    let weak_popup = popup.downgrade();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            if let Some(popup) = weak_popup.upgrade() {
                popup.close();
            }
            glib::Propagation::Stop
        } else {
            glib::Propagation::Proceed
        }
    });
    popup.add_controller(keys);
    let (sender, receiver) = mpsc::channel();
    let (consent_sender, consent_receiver) = mpsc::channel();
    let link = link.to_string();
    let flag = cancel.clone();
    std::thread::spawn(move || {
        inspect::run_with_redirects(&link, &sender, &flag, Some(&consent_receiver))
    });
    let weak_popup = popup.downgrade();
    let mut connections = 0;
    let mut route_complete = false;
    glib::timeout_add_local(Duration::from_millis(40), move || {
        if cancel.load(Ordering::Relaxed) || weak_popup.upgrade().is_none() {
            cancel.store(true, Ordering::Relaxed);
            return glib::ControlFlow::Break;
        }
        loop {
            match receiver.try_recv() {
                Ok(Event::Dns(name, ips)) => {
                    address_count.set_text(&format!(
                        "{} address{}",
                        ips.len(),
                        if ips.len() == 1 { "" } else { "es" }
                    ));
                    let all = ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("\n");
                    addresses.set_text(
                        &ips.iter()
                            .take(3)
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                    addresses.set_tooltip_text(Some(&all));
                    dns_note.set_text(if ips.len() > 3 {
                        "More addresses in Details & privacy"
                    } else {
                        "A + AAAA · system resolver"
                    });
                    dns.set_tooltip_text(Some(&name));
                }
                Ok(Event::Connection {
                    url,
                    secure,
                    status: code,
                    elapsed_ms,
                    peer,
                    certificate,
                }) => {
                    connections += 1;
                    tls.set_text("Checking route…");
                    tls.remove_css_class("success");
                    tls.remove_css_class("warning-text");

                    response.set_text(&format!(
                        "Last {} · HTTP {code} · {elapsed_ms:.0} ms",
                        if secure { "HTTPS" } else { "HTTP" }
                    ));
                    response
                        .set_tooltip_text(Some(&format!("{connections} connection(s) · {url}")));
                    match certificate {
                        Some(Ok(info)) => {
                            subject.set_text(&format!("Issued to: {}", info.subject));
                            issuer.set_text(&format!("Signed by: {}", info.issuer));
                            subject.set_tooltip_text(Some(&info.detail));
                            issuer.set_tooltip_text(Some(&info.detail));
                        }
                        Some(Err(error)) => {
                            subject.set_text("Issued to: unavailable");
                            issuer.set_text("Signed by: unavailable");
                            subject.set_tooltip_text(Some(&error));
                            issuer.set_tooltip_text(Some(&error));
                        }
                        None => {
                            subject.set_text("Issued to: no TLS certificate");
                            issuer.set_text("Signed by: not applicable (HTTP)");
                            subject.set_tooltip_text(None);
                            issuer.set_tooltip_text(None);
                        }
                    }
                    if let Some(ip) = peer {
                        let index = add_peer(&peers, &peer_names, ip);
                        selector.set_selected(index as u32);
                    }
                }
                Ok(Event::Assessment {
                    encrypted,
                    complete,
                }) => {
                    route_complete = complete;
                    let (label, class) = assessment_style(encrypted, complete);
                    tls.set_text(label);
                    tls.remove_css_class("success");
                    tls.remove_css_class("warning-text");
                    tls.add_css_class(class);
                    trust.set_text(if encrypted && complete {
                        "Certificate valid · site trust unknown"
                    } else if complete {
                        "HTTP observed · site trust unknown"
                    } else {
                        "Route incomplete · site trust unknown"
                    });
                }
                Ok(Event::Location(ip, result)) => {
                    let index = add_peer(&peers, &peer_names, ip);
                    peers.borrow_mut()[index].location = Some(result);
                }
                Ok(Event::Probe(ip, value)) => {
                    let index = add_peer(&peers, &peer_names, ip);
                    peers.borrow_mut()[index].samples.values.push(value);
                }
                Ok(Event::PingUnavailable(ip, error)) => {
                    let index = add_peer(&peers, &peer_names, ip);
                    peers.borrow_mut()[index].ping_error = Some(error);
                }
                Ok(Event::Section(title, detail)) => {
                    append_log(&log, &title, &detail);
                    if matches!(
                        title.as_str(),
                        "Check stopped"
                            | "DNS unavailable"
                            | "Connection could not be verified"
                            | "Redirect stopped"
                            | "Internationalized hostname"
                            | "Proxy configuration detected"
                    ) {
                        notice.set_text(&title);
                        notice.set_tooltip_text(Some(&detail));
                        banner.set_reveal_child(true);
                        if title == "Proxy configuration detected" {
                            address_count.set_text("Proxy mode");
                            addresses.set_text("Separate DNS and ping checks skipped");
                        }
                        if matches!(
                            title.as_str(),
                            "Check stopped"
                                | "DNS unavailable"
                                | "Connection could not be verified"
                        ) && connections == 0
                        {
                            tls.set_text("Not verified");
                            subject.set_text("Issued to: unavailable");
                            issuer.set_text("Signed by: unavailable");
                            response.set_text(&title);
                            response.set_tooltip_text(Some(&detail));
                        }
                    }
                }
                Ok(Event::Peer(ip)) => {
                    if peers
                        .borrow()
                        .get(selected.get())
                        .is_some_and(|peer| peer.ip == ip)
                    {
                        geo.set_tooltip_text(Some(&format!(
                            "Optional online lookup for {ip}; click to review what is shared."
                        )));
                    }
                }
                Ok(Event::PublicHost(name)) => {
                    reputation(&reputation_button, &name, &reputation_result);
                    match crate::whois::prepare(&name) {
                        Ok(lookup) => {
                            let disclosure = format!(
                                "Look up registration for {} at {}? Only this registered domain is sent; subdomains, paths, queries and fragments are omitted. Provider selection uses a bundled IANA map. The registry may log the domain and your connection IP. No registrar referrals or redirects are followed. This describes the initial domain, not every redirect.",
                                lookup.domain, lookup.url
                            );
                            online_lookup(
                                &whois,
                                &disclosure,
                                &whois_result,
                                &log,
                                &cancel,
                                move |cancel| crate::whois::run(&lookup, cancel),
                            );
                        }
                        Err(reason) => {
                            whois_result.set_text("Unavailable");
                            whois.set_tooltip_text(Some(&reason));
                            whois_result.set_tooltip_text(Some(&reason));
                        }
                    }
                }
                Ok(Event::Redirect(link)) => {
                    notice.set_text("Another origin · paused before connecting");
                    notice.set_tooltip_text(Some(&link));
                    banner.set_reveal_child(true);
                    let button = menu("Review redirect →");
                    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
                    content.append(&wrapped(&format!("Continue inspection at {link}? This sends its path and query to that destination.")));
                    let confirm = gtk::Button::with_label("Inspect this destination");
                    confirm.add_css_class("route");
                    content.append(&confirm);
                    button.set_popover(Some(&popover(&content)));
                    spinner.stop();
                    status.set_text("Waiting for consent");
                    let consent = consent_sender.clone();
                    let weak_button = button.downgrade();
                    confirm.connect_clicked(move |confirm| {
                        confirm.set_sensitive(false);
                        if let Some(button) = weak_button.upgrade() {
                            if let Some(pop) = button.popover() {
                                pop.popdown();
                            }
                            button.set_visible(false);
                        }
                        let _ = consent.send(());
                    });
                    warning.append(&button);
                }
                Ok(Event::Resumed) => {
                    banner.set_reveal_child(false);
                    spinner.set_visible(true);
                    spinner.start();
                    status.set_text("Checking…");
                    tls.set_text("Checking route…");
                    tls.remove_css_class("success");
                }
                Ok(Event::Insights(report, names)) => {
                    *checked_hosts.lock().unwrap() = names;
                    insights_view.render(&report);
                }
                Ok(Event::Done) => {
                    done.set(true);
                    spinner.stop();
                    spinner.set_visible(false);
                    status.set_text(if route_complete {
                        "Checks finished"
                    } else {
                        "Incomplete"
                    });
                    if connections == 0 && addresses.text() == "Your configured DNS resolver" {
                        address_count.set_text("Unavailable");
                    }
                    peer_view.render(peers.borrow().get(selected.get()), true);
                    return glib::ControlFlow::Break;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    peer_view.render(peers.borrow().get(selected.get()), done.get());
                    return glib::ControlFlow::Continue;
                }
                Err(_) => {
                    spinner.stop();
                    status.set_text("Checks stopped");
                    return glib::ControlFlow::Break;
                }
            }
        }
    });
    popup.present();
    GtkWindowExt::set_focus(&popup, None::<&gtk::Widget>);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "GTK regression: run under Xvfb with --test-threads=1"]
    fn peer_change_discards_a_late_online_lookup() {
        gtk::init().unwrap();
        let button = menu("Lookup");
        let output = text("Not checked", "footer");
        let log = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
        let cancel = Arc::new(AtomicBool::new(false));
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let gate_copy = gate.clone();
        let old_finished = Arc::new(AtomicBool::new(false));
        let finished = old_finished.clone();
        online_lookup(&button, "First peer", &output, &log, &cancel, move |_| {
            let (lock, ready) = &*gate_copy;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
            finished.store(true, Ordering::Relaxed);
            Ok("OLD PEER".into())
        });
        let confirm = |button: &gtk::MenuButton| {
            let mut child = button.popover().unwrap().child().unwrap().first_child();
            while let Some(widget) = child {
                if let Ok(button) = widget.clone().downcast::<gtk::Button>() {
                    button.emit_clicked();
                    return;
                }
                child = widget.next_sibling();
            }
            panic!("Missing confirmation button");
        };
        // Keep the old popover alive, as a compositor animation can do.
        let old_popover = button.popover().unwrap();
        confirm(&button);
        online_lookup(&button, "Second peer", &output, &log, &cancel, |_| {
            Ok("NEW PEER".into())
        });
        confirm(&button);
        let pump_until = |condition: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while !condition() && std::time::Instant::now() < deadline {
                while glib::MainContext::default().iteration(false) {}
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(condition(), "GTK result did not arrive");
        };
        pump_until(&|| output.text() == "NEW PEER");
        *gate.0.lock().unwrap() = true;
        gate.1.notify_one();
        pump_until(&|| old_finished.load(Ordering::Relaxed));
        let deadline = std::time::Instant::now() + Duration::from_millis(150);
        pump_until(&|| std::time::Instant::now() >= deadline);
        assert_eq!(output.text(), "NEW PEER");
        assert_eq!(output.tooltip_text().unwrap(), "NEW PEER");
        assert!(
            !log.text(&log.start_iter(), &log.end_iter(), false)
                .contains("OLD PEER")
        );
        drop(old_popover);
    }

    #[test]
    fn incomplete_and_mixed_routes_never_get_a_green_assessment() {
        assert_eq!(
            assessment_style(true, false),
            ("Inspection incomplete", "warning-text")
        );
        assert_eq!(
            assessment_style(false, false),
            ("Inspection incomplete", "warning-text")
        );
        assert_eq!(
            assessment_style(false, true),
            ("Route includes HTTP", "warning-text")
        );
        assert_eq!(assessment_style(true, true), ("Verified HTTPS", "success"));
    }
    #[test]
    fn country_flags_validate_codes() {
        assert_eq!(flag("NL"), "🇳🇱");
        assert_eq!(flag("ca"), "🇨🇦");
        for invalid in ["", "USA", "1A", "é"] {
            assert_eq!(flag(invalid), "🌐");
        }
    }
    #[test]
    fn missing_probes_are_not_zero_latency() {
        let samples = Samples {
            values: vec![Some(10.0), None, Some(30.0), None],
        };
        let (average, stats) = samples.summary();
        assert_eq!(average, "20.0 ms");
        assert!(stats.contains("50% loss"));
        assert_eq!(
            Samples {
                values: vec![None; 8]
            }
            .summary()
            .0,
            "No replies"
        );
        assert_eq!(Samples::default().summary().0, "Waiting…");
    }
}
