use crate::{
    inspect::{self, Cancel, Event, Location, PROBE_COUNT},
    relay::{Action, execute_gui},
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

const PRIVACY: &str = "Inspect sends the path and query to the destination using HEAD requests. Your DNS resolver sees queried hostnames. Ping stays off until separately confirmed for the selected peer: eight ICMP probes disclose your source IP, target IP and timing to the destination and networks along the route. The payload is 16 zero bytes; no hostname, URL or credentials are included. Switching peers never starts probes, and closing the inspector cancels them. Same-origin redirects are followed. Another origin requires a separate click; HTTPS downgrades are stopped. Fragments and credentials are never sent. No cookies, page scripts, or embedded resources are loaded.\n\nTranco and OISD match cached domain lists locally. Tranco includes subdomains, checks exact names first, and labels parent-only matches. Popularity never overrides a blocklist warning. Big combines ads/tracking and security threats; NSFW is a separate adult/shock list. A match is not a malware verdict, and no match is not proof of safety. Explicit list updates download the full lists without sending inspected hostnames or URLs.\n\nRisk factors are computed on this device from the observed route, certificates and the local Tranco index (lookalike names). They send nothing. They are reasons to look closer; finding none does not mean a site is safe.\n\nGeoIP uses a local database. Locations are approximate and may describe a CDN or proxy rather than the origin. Proxy settings are respected; separate DNS and ping checks are skipped when a proxy is configured.\n\nEmbedded certificate-transparency signatures are verified locally with signed log metadata. Updating log keys contacts www.gstatic.com for two fixed public files, never an inspected hostname or certificate. These are logging promises, not inclusion proofs or site-safety checks. The log snapshot date and limitations are shown under CT. Certificate history is opt-in and sends the exact initial public hostname (including its subdomain) and your IP to SSLMate Cert Spotter; no link path, query or fragment is sent. Each click requests one page of unexpired issuances; further pages need another click. An optional API key identifies your Cert Spotter account, stays in memory and is sent only to that service. Log inclusion has its own confirmation: two requests send a certificate-identifying log-entry hash to the named log. Signed tree heads and Merkle proofs are checked locally; this is not a consistency audit or a safety verdict.\n\nOnline GeoIP, VirusTotal and WHOIS / RDAP stay off until explicitly requested. WHOIS sends only the registered domain to the registry shown in the disclosure; a bundled IANA map and public-suffix list choose it locally. Referrals and redirects are never followed. Registration records can be redacted and do not verify the operator. Each lookup shows the exact public hostname or IP it shares. Services see your connection IP and may log the request. Private/reserved destinations are excluded. VirusTotal opens in your browser, where cookies, account identity, and other third parties may apply.\n\nHTTPS validates the connection, not the content. Popularity is not a safety score. ICMP can be blocked; a failed ping does not establish whether a site is safe.";

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
        &format!(
            "{disclosure}\n\nThe service sees your connection IP and may log this request. The link's path and query are not shared."
        ),
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

fn history_lookup<F>(
    button: &gtk::MenuButton,
    lookup: browser_relay::certificate_history::Lookup,
    output: &gtk::Label,
    log: &gtk::TextBuffer,
    cancel: &Cancel,
    task: F,
) where
    F: Fn(
            &browser_relay::certificate_history::Lookup,
            Option<&str>,
            &str,
            &Cancel,
        ) -> crate::Result<browser_relay::certificate_history::Page>
        + Send
        + Sync
        + 'static,
{
    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    content.append(&text("ONLY IF YOU CHOOSE", "eyebrow"));
    content.append(&wrapped(&lookup.disclosure));
    content.append(&wrapped(
        browser_relay::certificate_history::AUTH_DISCLOSURE,
    ));
    let key = gtk::PasswordEntry::builder()
        .placeholder_text("API key (optional, not saved)")
        .show_peek_icon(true)
        .build();
    key.add_css_class("history-key");
    content.append(&key);
    let confirm = gtk::Button::with_label("Look up first page");
    confirm.add_css_class("route");
    content.append(&confirm);
    let buffer = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
    let view = gtk::TextView::builder()
        .buffer(&buffer)
        .editable(false)
        .cursor_visible(false)
        .wrap_mode(gtk::WrapMode::WordChar)
        .build();
    view.add_css_class("inspection-log");
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&view)
        .visible(false)
        .build();
    scroll.set_size_request(400, 160);
    content.append(&scroll);
    button.set_popover(Some(&popover(&content)));
    button.set_sensitive(true);
    let cursor = Rc::new(RefCell::new(None::<String>));
    let seen = Rc::new(RefCell::new(std::collections::HashSet::<String>::new()));
    let busy = Rc::new(Cell::new(false));
    let task = Arc::new(task);
    let output = output.downgrade();
    let log = log.downgrade();
    let cancel = cancel.clone();
    let scroll = scroll.downgrade();
    confirm.connect_clicked(move |confirm| {
        if busy.replace(true) || cancel.load(Ordering::Relaxed) {
            return;
        }
        let secret = key.text().to_string();
        if let Err(error) = browser_relay::certificate_history::validate_key(&secret) {
            buffer.set_text(&error);
            if let Some(scroll) = scroll.upgrade() {
                scroll.set_visible(true);
            }
            busy.set(false);
            return;
        }
        confirm.set_sensitive(false);
        key.set_sensitive(false);
        if let Some(output) = output.upgrade() {
            output.set_text("Looking up…");
        }
        let lookup = lookup.clone();
        let after = cursor.borrow().clone();
        let flag = cancel.clone();
        let task = task.clone();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(task(&lookup, after.as_deref(), &secret, &flag));
        });
        let (cursor, seen, busy, cancel) =
            (cursor.clone(), seen.clone(), busy.clone(), cancel.clone());
        let (confirm, key, buffer) = (confirm.downgrade(), key.downgrade(), buffer.clone());
        let (output, log, scroll) = (output.clone(), log.clone(), scroll.clone());
        glib::timeout_add_local(Duration::from_millis(50), move || {
            if cancel.load(Ordering::Relaxed) {
                return glib::ControlFlow::Break;
            }
            let result = match receiver.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(_) => Err("Certificate history did not complete.".into()),
            };
            let Some(confirm) = confirm.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let mut message = match result {
                Ok(page) => {
                    let repeated = page
                        .next
                        .as_ref()
                        .is_some_and(|id| !seen.borrow_mut().insert(id.clone()));
                    // Bound local cursor tracking as well as each downloaded page.
                    let limit = seen.borrow().len() >= 100;
                    let more = page.next.is_some() && !repeated && !limit;
                    *cursor.borrow_mut() = page.next;
                    confirm.set_label(if more {
                        "Load next page"
                    } else {
                        "End of this lookup"
                    });
                    confirm.set_sensitive(more);
                    if repeated || limit {
                        format!(
                            "{}\nStopped at a repeated cursor or the 100-page session limit.",
                            page.summary
                        )
                    } else {
                        page.summary
                    }
                }
                Err(error) => {
                    confirm.set_label("Retry this page");
                    confirm.set_sensitive(true);
                    format!("Unavailable: {error}")
                }
            };
            if message.len() > 8192 {
                message = message.chars().take(2048).collect();
            }
            if let Some(output) = output.upgrade() {
                output.set_text(message.lines().next().unwrap_or("No result"));
                output.set_tooltip_text(Some(&message));
            }
            buffer.set_text(&message);
            if let Some(scroll) = scroll.upgrade() {
                scroll.set_visible(true);
            }
            if let Some(log) = log.upgrade() {
                append_log(&log, "Optional certificate history", &message);
            }
            if let Some(key) = key.upgrade() {
                key.set_sensitive(true);
            }
            busy.set(false);
            glib::ControlFlow::Break
        });
    });
}

fn popularity_scale() -> (gtk::DrawingArea, Rc<Cell<Option<f64>>>) {
    let scale = gtk::DrawingArea::builder()
        .content_height(8)
        .hexpand(true)
        .build();
    let position = Rc::new(Cell::new(None));
    let current = position.clone();
    scale.set_draw_func(move |_, cr, width, height| {
        let position = current.get();
        let width = f64::from(width);
        let middle = f64::from(height) / 2.0;
        let gradient = gtk::cairo::LinearGradient::new(3.0, 0.0, width - 3.0, 0.0);
        for stop in [0.0, 0.5, 1.0] {
            let [r, g, b] = browser_relay::insights::popularity_rgb(stop);
            gradient.add_color_stop_rgb(
                stop,
                f64::from(r) / 255.0,
                f64::from(g) / 255.0,
                f64::from(b) / 255.0,
            );
        }
        if position.is_some() {
            let _ = cr.set_source(&gradient);
        } else {
            cr.set_source_rgb(0.5, 0.47, 0.55);
        }
        cr.rectangle(3.0, middle - 2.0, (width - 6.0).max(0.0), 4.0);
        let _ = cr.fill();
        if let Some(position) = position {
            cr.arc(
                3.0 + position * (width - 6.0).max(0.0),
                middle,
                3.0,
                0.0,
                std::f64::consts::TAU,
            );
            cr.set_source_rgb(0.1, 0.08, 0.15);
            let _ = cr.fill_preserve();
            cr.set_source_rgb(1.0, 1.0, 1.0);
            cr.set_line_width(1.0);
            let _ = cr.stroke();
        }
    });
    (scale, position)
}

#[derive(Clone)]
struct InsightsView {
    rank: gtk::Label,
    rank_caption: gtk::Label,
    rank_scale: gtk::DrawingArea,
    rank_position: Rc<Cell<Option<f64>>>,
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
        self.rank.set_attributes(None);
        if rank.position.is_none() {
            self.rank.add_css_class("list-unknown");
        } else {
            self.rank.remove_css_class("list-unknown");
        }
        if let Some(position) = rank.position {
            let [r, g, b] = browser_relay::insights::popularity_rgb(position);
            let attributes = gtk::pango::AttrList::new();
            attributes.insert(gtk::pango::AttrColor::new_foreground(
                u16::from(r) * 257,
                u16::from(g) * 257,
                u16::from(b) * 257,
            ));
            self.rank.set_attributes(Some(&attributes));
        }
        self.rank_position.set(rank.position);
        self.rank_scale.queue_draw();
        self.rank_scale.set_tooltip_text(Some(&match rank.position {
            Some(position) => format!("Popularity: {position:.3} · 0 green = #1 · 1 red = #1,000,000 / outside index. Logarithmic rank with arctangent smoothing. Not a safety score."),
            None => "Popularity unavailable or not applicable.".into(),
        }));
        self.rank_caption.set_text(&rank.caption);
        self.rank.set_tooltip_text(Some(&rank.detail));
        self.rank_caption.set_tooltip_text(Some(&rank.detail));
        let report = &combined.oisd;
        for (label, matched, adult) in [
            (&self.big, report.big, false),
            (&self.nsfw, report.nsfw, true),
        ] {
            label.set_text(match matched {
                Some(true) if adult => "Adult match",
                Some(true) => "Listed",
                Some(false) => "No match",
                None => "Unknown",
            });
            for class in ["list-match", "list-adult", "list-neutral", "list-unknown"] {
                label.remove_css_class(class);
            }
            label.add_css_class(match matched {
                Some(true) if adult => "list-adult",
                Some(true) => "list-match",
                Some(false) => "list-neutral",
                None => "list-unknown",
            });
        }
        self.note.set_text(&report.note(rank));
        self.note.set_tooltip_text(Some("Green means no match in the loaded lists, not a safety guarantee. Red is an OISD Big match; orange is an adult/shock-content match. Popularity is separate."));
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

fn severity_style(severity: browser_relay::risk::Severity) -> (&'static str, &'static str) {
    use browser_relay::risk::Severity;
    // Adwaita has no emblem-default-symbolic, and a check mark would read as
    // an all-clear; the severity word and colour tell cautions and notices apart.
    match severity {
        Severity::Warning => ("dialog-warning-symbolic", "risk-warning"),
        Severity::Caution => ("dialog-information-symbolic", "risk-caution"),
        Severity::Notice => ("dialog-information-symbolic", "risk-notice"),
    }
}

fn comparison_markup(shown: &str, brand: &str) -> String {
    let (prefix, suffix) = browser_relay::risk::differing_span(shown, brand);
    let mark = |value: &str| {
        let chars: Vec<char> = value.chars().collect();
        let end = chars.len() - suffix;
        let part = |range: std::ops::Range<usize>| {
            glib::markup_escape_text(&chars[range].iter().collect::<String>()).to_string()
        };
        format!(
            "{}<span weight=\"bold\" underline=\"single\" foreground=\"#ffc27d\">{}</span>{}",
            part(0..prefix),
            part(prefix..end),
            part(end..chars.len())
        )
    };
    format!("This link   {}\nLooks like  {}", mark(shown), mark(brand))
}

/// GtkExpander never links its label widget as labelled-by, and GTK before
/// 4.14 computes no name from content. Builder's <accessibility> sets the
/// name on GTK 4.0 without a newer gtk4-rs feature.
fn expander_ui(label: &str) -> String {
    format!(
        "<interface><object class=\"GtkExpander\" id=\"row\"><accessibility><property name=\"label\">{}</property></accessibility></object></interface>",
        glib::markup_escape_text(label)
    )
}

fn labelled_expander(label: &str) -> gtk::Expander {
    let builder = gtk::Builder::new();
    builder
        .add_from_string(&expander_ui(label))
        .ok()
        .and_then(|_| builder.object::<gtk::Expander>("row"))
        .unwrap_or_default()
}

fn row_key(factor: &browser_relay::risk::Factor) -> String {
    format!("{}\u{1f}{}", factor.id, factor.title)
}

/// Owns the card's widgets and last state; re-renders only on change and
/// keeps each row's expanded state across updates.
#[derive(Clone)]
struct RiskView {
    disclosure: gtk::Expander,
    available: Rc<Cell<bool>>,
    summary: gtk::Label,
    rows: gtk::Box,
    missing: gtk::Box,
    shield: gtk::Image,
    factors: Rc<RefCell<Vec<browser_relay::risk::Factor>>>,
    finished: Rc<Cell<bool>>,
    complete: Rc<Cell<bool>>,
}
impl RiskView {
    fn update(&self, factors: Vec<browser_relay::risk::Factor>, lookalikes: bool) {
        self.missing.set_visible(!lookalikes);
        self.available.set(lookalikes);
        let new_warning = factors.iter().any(|f| {
            f.severity == browser_relay::risk::Severity::Warning
                && !self
                    .factors
                    .borrow()
                    .iter()
                    .any(|old| old.severity == f.severity && row_key(old) == row_key(f))
        });
        if new_warning {
            self.disclosure.set_expanded(true);
        }
        if *self.factors.borrow() != factors {
            *self.factors.borrow_mut() = factors;
            self.rebuild_rows();
        }
        self.render_summary();
    }
    fn finish(&self, complete: bool) {
        self.finished.set(true);
        self.complete.set(complete);
        self.render_summary();
    }
    /// Checking resumed after a consent pause.
    fn resume(&self) {
        self.finished.set(false);
        self.render_summary();
    }
    fn render_summary(&self) {
        let factors = self.factors.borrow();
        let (text, highest) =
            browser_relay::risk::summary(&factors, self.finished.get(), self.complete.get());
        let text = if self.available.get() {
            text
        } else {
            format!("{text} · lookalikes off")
        };
        self.summary.set_text(&text);
        self.summary.set_tooltip_text(Some(&text));
        for class in ["risk-warning", "risk-caution", "risk-notice", "risk-none"] {
            self.summary.remove_css_class(class);
        }
        self.summary
            .add_css_class(highest.map_or("risk-none", |s| severity_style(s).1));
        let warned = highest == Some(browser_relay::risk::Severity::Warning);
        self.shield.set_icon_name(Some(if warned {
            "dialog-warning-symbolic"
        } else {
            "security-high-symbolic"
        }));
        if warned {
            self.shield.add_css_class("risk-warning");
        } else {
            self.shield.remove_css_class("risk-warning");
        }
    }
    fn rebuild_rows(&self) {
        let mut previous = std::collections::HashMap::new();
        let focus = self.rows.root().and_then(|root| root.focus());
        let mut focused = None;
        while let Some(child) = self.rows.first_child() {
            if let Ok(expander) = child.clone().downcast::<gtk::Expander>() {
                let key = expander.widget_name().to_string();
                if focus
                    .as_ref()
                    .is_some_and(|widget| widget == &child || widget.is_ancestor(&child))
                {
                    focused = Some(key.clone());
                }
                previous.insert(key, expander.is_expanded());
            }
            self.rows.remove(&child);
        }
        for factor in self.factors.borrow().iter() {
            let key = row_key(factor);
            let expanded = previous
                .get(&key)
                .copied()
                .unwrap_or(factor.severity == browser_relay::risk::Severity::Warning);
            let (icon, class) = severity_style(factor.severity);
            let head = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let image = gtk::Image::from_icon_name(icon);
            image.add_css_class(class);
            head.append(&image);
            let title = text(&factor.title, "risk-title");
            title.set_ellipsize(gtk::pango::EllipsizeMode::End);
            title.set_hexpand(true);
            title.set_xalign(0.0);
            // On the title only, so it never covers the expanded evidence.
            title.set_tooltip_text(Some(&factor.title));
            head.append(&title);
            let tag = text(factor.severity.word(), "risk-tag");
            tag.add_css_class(class);
            // The word carries severity alongside the colour; never truncate it.
            tag.set_ellipsize(gtk::pango::EllipsizeMode::None);
            head.append(&tag);
            let detail = gtk::Box::new(gtk::Orientation::Vertical, 4);
            detail.add_css_class("risk-detail");
            if let Some((shown, brand)) = &factor.compare {
                let compare = gtk::Label::new(None);
                compare.set_markup(&comparison_markup(shown, brand));
                compare.add_css_class("risk-compare");
                compare.set_xalign(0.0);
                compare.set_selectable(true);
                compare.set_focusable(false);
                detail.append(&compare);
            }
            let evidence = wrapped(&factor.evidence);
            evidence.set_selectable(true);
            evidence.set_focusable(false);
            detail.append(&evidence);
            let expander =
                labelled_expander(&format!("{}: {}", factor.severity.word(), factor.title));
            expander.set_label_widget(Some(&head));
            expander.set_child(Some(&detail));
            expander.set_expanded(expanded);
            expander.set_widget_name(&key);
            self.rows.append(&expander);
            // Rebuilding must not drop keyboard focus from the row being read.
            if focused.as_deref() == Some(key.as_str()) {
                expander.grab_focus();
            }
        }
    }
}

fn reputation(
    button: &gtk::MenuButton,
    name: &str,
    status: &gtk::Label,
    browser: Option<crate::browser::Browser>,
) {
    let Ok(url) = inspect::reputation_url(name) else {
        return;
    };
    let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
    content.append(&text("VIRUSTOTAL REPORT", "eyebrow"));
    content.append(&wrapped(&format!("Shares {name} with VirusTotal in your browser. The original path and query are not sent. Your browser may share cookies, account identity and other request data. The report describes this initial host, not every redirect.")));
    let confirm = gtk::Button::with_label(
        &browser
            .as_ref()
            .map(|b| format!("Open in {} ↗", b.name))
            .unwrap_or_else(|| "No browser available".into()),
    );
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
        if let Some(browser) = &browser {
            let browser = browser.clone();
            let url = url.clone();
            let status = status.clone();
            glib::MainContext::default().spawn_local(async move {
                let result = execute_gui(Action::Browser(browser), vec![url]).await;
                if let Some(status) = status.upgrade() {
                    status.set_text(
                        &result
                            .map(|_| "Opened in browser".into())
                            .unwrap_or_else(|e| e),
                    );
                }
            });
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
    ping_started: bool,
    ping_running: bool,
}
#[derive(Clone)]
struct PeerView {
    flag: gtk::Label,
    location: gtk::Label,
    note: gtk::Label,
    average: gtk::Label,
    stats: gtk::Label,
    chart: gtk::DrawingArea,
    chart_revealer: gtk::Revealer,
    ping_button: gtk::MenuButton,
}
impl PeerView {
    fn render(&self, peer: Option<&Peer>, done: bool) {
        self.chart_revealer
            .set_reveal_child(peer.is_some_and(|p| p.ping_running || !p.samples.values.is_empty()));
        self.ping_button
            .set_sensitive(peer.is_some_and(|p| !p.ping_running) && !inspect::proxy_configured());
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
        self.ping_button.set_label(if peer.ping_running {
            "Pinging…"
        } else if peer.ping_started {
            "Ping again…"
        } else {
            "Ping…"
        });
        if inspect::proxy_configured() {
            self.average.set_text("Disabled");
            self.stats.set_text("Ping skipped · proxy configured");
        } else if let Some(error) = &peer.ping_error {
            self.average.set_text("Not measured");
            self.stats.set_text(error);
            self.stats.set_tooltip_text(Some(error));
        } else if !peer.ping_started {
            self.average.set_text("Not measured");
            self.stats.set_text("Opt-in · no probes sent");
            self.stats.set_tooltip_text(None);
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
        ping_started: false,
        ping_running: false,
    });
    names.append(&ip.to_string());
    index
}
fn ping_consent(
    button: &gtk::MenuButton,
    ip: IpAddr,
    sender: &mpsc::Sender<Event>,
    cancel: &Cancel,
    peers: &Rc<RefCell<Vec<Peer>>>,
) {
    let peers = peers.clone();
    let events = sender.clone();
    let updates = sender.clone();
    confirmed_task(
        button,
        &format!(
            "Send {PROBE_COUNT} ICMP ping probes to {ip}? The destination and networks along the route can observe your source IP, this target IP and timing. Each payload is 16 zero bytes: no hostname, URL, cookies or credentials. This measures responsiveness, not trust. Only this IP is probed; no other peer or future inspection is authorized. Closing the inspector cancels remaining probes."
        ),
        "Send 8 probes",
        cancel,
        move |cancel| inspect::probe_peer(ip, &events, cancel),
        move |state| {
            let event = match state {
                LookupState::Running => {
                    // Mark busy synchronously so rapid peer changes cannot offer
                    // a second batch before the event queue is drained.
                    if let Some(peer) = peers.borrow_mut().iter_mut().find(|p| p.ip == ip) {
                        peer.ping_running = true;
                    }
                    Event::PingStarted(ip)
                }
                LookupState::Complete(result) => Event::PingFinished(ip, result),
            };
            let _ = updates.send(event);
        },
    );
    button.set_sensitive(!inspect::proxy_configured());
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

pub fn show(
    parent: &gtk::Window,
    link: &str,
    multiple: bool,
    browser: Option<crate::browser::Browser>,
    on_close: impl Fn(&[browser_relay::risk::Factor]) + 'static,
) {
    let popup = gtk::Window::builder()
        .title("Inspect link")
        .transient_for(parent)
        .modal(true)
        .destroy_with_parent(true)
        .default_width(800)
        .default_height(780)
        .icon_name("browser-relay")
        .build();
    popup.add_css_class("relay");
    popup.add_css_class("dashboard");
    let header = gtk::HeaderBar::new();
    header.set_decoration_layout(Some(":close"));
    header.set_title_widget(Some(&text("LINK INSPECTION", "brand")));
    popup.set_titlebar(Some(&header));
    let body = gtk::Box::new(gtk::Orientation::Vertical, 8);
    body.set_margin_start(24);
    body.set_margin_end(24);
    body.set_margin_top(10);
    body.set_margin_bottom(4);
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

    let risk_card = gtk::Box::new(gtk::Orientation::Vertical, 0);
    risk_card.add_css_class("dashboard-card");
    risk_card.add_css_class("risk-card");
    let risk_disclosure = labelled_expander("Risk factors and evidence");
    let risk_header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let risk_heading = text("RISK FACTORS", "eyebrow");
    risk_heading.set_ellipsize(gtk::pango::EllipsizeMode::None);
    risk_header.append(&risk_heading);
    let risk_summary = text("Checking the route…", "risk-summary");
    risk_summary.set_max_width_chars(80);
    risk_summary.set_hexpand(true);
    risk_summary.add_css_class("risk-none");
    risk_header.append(&risk_summary);
    risk_disclosure.set_label_widget(Some(&risk_header));
    let risk_details = gtk::Box::new(gtk::Orientation::Vertical, 6);
    risk_disclosure.set_child(Some(&risk_details));
    risk_card.append(&risk_disclosure);
    let risk_rows = gtk::Box::new(gtk::Orientation::Vertical, 2);
    risk_details.append(&risk_rows);
    let risk_missing = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    let missing_note = text("Lookalike checks are off · no local ranking list", "footer");
    missing_note.set_hexpand(true);
    risk_missing.append(&missing_note);
    let download_lists = gtk::Button::with_label("Download lists…");
    download_lists.add_css_class("route");
    download_lists.add_css_class("compact");
    risk_missing.append(&download_lists);
    risk_missing.set_visible(false);
    risk_details.append(&risk_missing);
    risk_details.append(&text(
        "Checked on this device · expand a row for evidence and what to do",
        "footer",
    ));
    body.append(&risk_card);
    let risk_view = RiskView {
        disclosure: risk_disclosure,
        available: Rc::new(Cell::new(false)),
        summary: risk_summary,
        rows: risk_rows,
        missing: risk_missing,
        shield: shield.clone(),
        factors: Rc::new(RefCell::new(Vec::new())),
        finished: Rc::new(Cell::new(false)),
        complete: Rc::new(Cell::new(false)),
    };
    // Generation + latest facts, so a list update never replaces newer factors.
    let last_facts = Arc::new(std::sync::Mutex::new((
        0u64,
        None::<browser_relay::risk::Facts>,
    )));

    let grid = gtk::Grid::builder()
        .column_spacing(12)
        .row_spacing(12)
        .column_homogeneous(true)
        .vexpand(false)
        .build();
    let connection = card("CONNECTION SECURITY");
    let ct = menu("CT");
    ct.add_css_class("certificate-menu");
    ct.set_tooltip_text(Some(
        "Local Certificate Transparency checks and optional certificate history",
    ));
    let ct_content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    let ct_detail = wrapped("No certificate has been checked yet.");
    let ct_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .propagate_natural_height(true)
        .max_content_height(280)
        .min_content_width(380)
        .child(&ct_detail)
        .build();
    ct_scroll.set_size_request(380, -1);
    ct_content.append(&ct_scroll);
    let inclusion = menu("Verify log inclusion…");
    inclusion.set_sensitive(false);
    let inclusion_result = wrapped("Opt-in · one supported log · certificate-identifying hash");
    ct_content.append(&inclusion);
    ct_content.append(&inclusion_result);
    let history = menu("Certificate history…");
    history.set_sensitive(false);
    history.set_tooltip_text(Some(
        "Available for the initial public hostname after direct inspection; disabled with a proxy.",
    ));
    let history_result = wrapped("Opt-in · SSLMate Cert Spotter · unexpired issuances");
    ct_content.append(&history);
    ct_content.append(&history_result);
    let update_ct = menu("Update log keys…");
    let ct_update_result = wrapped("Signed metadata · downloaded only on request");
    ct_content.append(&update_ct);
    ct_content.append(&ct_update_result);
    ct.set_popover(Some(&popover(&ct_content)));
    let heading = connection.first_child().unwrap();
    connection.remove(&heading);
    heading.set_hexpand(true);
    let connection_heading = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    connection_heading.append(&heading);
    connection_heading.append(&ct);
    connection.append(&connection_heading);
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
    let ping_button = menu("Ping…");
    ping_button.add_css_class("certificate-menu");
    ping_button.set_sensitive(false);
    ping_button.set_tooltip_text(Some("Optional · review the selected IP and privacy disclosure before sending probes. Disabled with a proxy."));
    let ping_title = ping.first_child().unwrap();
    ping.remove(&ping_title);
    ping_title.set_hexpand(true);
    let ping_heading = gtk::Box::new(gtk::Orientation::Horizontal, 4);
    ping_heading.append(&ping_title);
    ping_heading.append(&ping_button);
    ping.append(&ping_heading);
    let average = text("Not measured", "dashboard-value");
    ping.append(&average);
    let bars = chart(peers.clone(), selected.clone());
    let chart_revealer = gtk::Revealer::builder()
        .transition_type(gtk::RevealerTransitionType::SlideDown)
        .transition_duration(180)
        .child(&bars)
        .build();
    ping.append(&chart_revealer);
    let stats = text("Opt-in · no probes sent", "footer");
    ping.append(&stats);
    grid.attach(&ping, 1, 1, 1, 1);
    body.append(&grid);

    let cancel: Cancel = Arc::new(AtomicBool::new(false));
    let log = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
    log.set_text(PRIVACY);
    let result_label = ct_update_result.downgrade();
    let update_log = log.downgrade();
    confirmed_task(
        &update_ct,
        browser_relay::ct_logs::DISCLOSURE,
        "Download log keys",
        &cancel,
        crate::ct_transport::update_logs,
        move |state| {
            let Some(label) = result_label.upgrade() else {
                return;
            };
            match state {
                LookupState::Running => label.set_text("Updating log keys…"),
                LookupState::Complete(result) => {
                    let message = result.unwrap_or_else(|e| format!("Unavailable: {e}"));
                    label.set_text(&message);
                    if let Some(log) = update_log.upgrade() {
                        append_log(&log, "CT log update", &message);
                    }
                }
            }
        },
    );
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
    let weak_update = update_lists.downgrade();
    download_lists.connect_clicked(move |_| {
        if let Some(button) = weak_update.upgrade() {
            // Focus scrolls the list card into view so the popover is anchored visibly.
            button.grab_focus();
            button.popup();
        }
    });
    let list_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    list_row.set_homogeneous(true);
    let (rank_tile, rank_state, rank_caption) =
        list_tile("TRANCO · POPULARITY", "Includes subdomains");
    rank_tile.add_css_class("popularity-tile");
    let (rank_scale, rank_position) = popularity_scale();
    rank_tile.append(&rank_scale);
    let (big_tile, big_state, _) = list_tile("OISD · BLOCKLIST", "Ads, tracking & threats");
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
        rank_scale,
        rank_position,
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
    let facts_for_update = last_facts.clone();
    let view_for_update = risk_view.clone();
    let current_facts = last_facts.clone();
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
            let (generation, facts) = facts_for_update.lock().unwrap().clone();
            let risk = facts
                .as_ref()
                .map(|facts| (generation, crate::tranco::risk(facts)));
            Ok((
                crate::reputation::check(&names),
                names,
                message,
                failed,
                risk,
            ))
        },
        move |state| match state {
            LookupState::Running => view.note.set_text("Updating…"),
            LookupState::Complete(result) => {
                let detail = match result {
                    Ok((report, names, message, failed, risk)) => {
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
                        if let Some((generation, (factors, lookalikes))) = risk
                            && current_facts.lock().unwrap().0 == generation
                        {
                            view_for_update.update(factors, lookalikes);
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
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .vexpand(true)
        .child(&body)
        .build();
    // Pinned below the scrolled report so its actions stay visible at any height.
    footer.add_css_class("inspector-footer");
    let frame = gtk::Box::new(gtk::Orientation::Vertical, 0);
    frame.append(&scroll);
    frame.append(&footer);
    popup.set_child(Some(&frame));

    let peer_view = PeerView {
        flag: flag_label,
        location: place,
        note: location_note,
        average,
        stats,
        chart: bars,
        chart_revealer,
        ping_button,
    };
    let (sender, receiver) = mpsc::channel();
    let ping_sender = sender.clone();
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
        let peer_store = store.clone();
        let store = store.borrow();
        let peer = store.get(index);
        view.ping_button.set_popover(None::<&gtk::Popover>);
        if let Some(peer) = peer {
            ping_consent(&view.ping_button, peer.ip, &ping_sender, &flag, &peer_store);
        }
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
    let close_factors = risk_view.factors.clone();
    popup.connect_close_request(move |_| {
        flag.store(true, Ordering::Relaxed);
        on_close(&close_factors.borrow());
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
        let mut changed = false;
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
                    inclusion.set_sensitive(false);
                    inclusion.set_popover(None::<&gtk::Popover>);
                    inclusion_result.set_text("No supported inclusion proof available");
                    match certificate {
                        Some(Ok(info)) => {
                            if let Some(proof) = info.transparency.proof.clone() {
                                if !inspect::proxy_configured()
                                    && peer.is_some_and(inspect::public_ip)
                                {
                                    inclusion_result.set_text(
                                        "Opt-in · one log · certificate-identifying hash",
                                    );
                                    online_lookup(
                                        &inclusion,
                                        &proof.disclosure(),
                                        &inclusion_result,
                                        &log,
                                        &cancel,
                                        move |cancel| {
                                            crate::ct_transport::inclusion(&proof, cancel)
                                        },
                                    );
                                } else {
                                    inclusion_result
                                        .set_text("Unavailable for proxy/private destinations");
                                }
                            }
                            ct.set_label(&format!(
                                "CT · {}",
                                info.transparency
                                    .summary
                                    .split_whitespace()
                                    .next()
                                    .filter(|s| s.contains('/'))
                                    .unwrap_or("unknown")
                            ));
                            ct_detail.set_text(&info.transparency.detail);
                            subject.set_text(&format!("Issued to: {}", info.subject));
                            issuer.set_text(&format!("Signed by: {}", info.issuer));
                            subject.set_tooltip_text(Some(&info.detail));
                            issuer.set_tooltip_text(Some(&info.detail));
                        }
                        Some(Err(error)) => {
                            ct.set_label("CT · unknown");
                            ct_detail.set_text(&error);
                            subject.set_text("Issued to: unavailable");
                            issuer.set_text("Signed by: unavailable");
                            subject.set_tooltip_text(Some(&error));
                            issuer.set_tooltip_text(Some(&error));
                        }
                        None => {
                            ct.set_label("CT · n/a");
                            ct_detail.set_text("No TLS certificate on this HTTP connection.");
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
                    risk_view.complete.set(complete);
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
                Ok(Event::PingStarted(ip)) => {
                    let index = add_peer(&peers, &peer_names, ip);
                    let mut peers = peers.borrow_mut();
                    let peer = &mut peers[index];
                    peer.samples.values.clear();
                    peer.ping_error = None;
                    peer.ping_started = true;
                    peer.ping_running = true;
                }
                Ok(Event::PingFinished(ip, result)) => {
                    let index = add_peer(&peers, &peer_names, ip);
                    let mut peers = peers.borrow_mut();
                    peers[index].ping_running = false;
                    if let Err(error) = &result {
                        peers[index].ping_error = Some(error.clone());
                    }
                    append_log(
                        &log,
                        &format!("Optional ping · {ip}"),
                        &result.unwrap_or_else(|e| e),
                    );
                }
                Ok(Event::Section(title, detail)) => {
                    append_log(&log, &title, &detail);
                    if matches!(
                        title.as_str(),
                        "Check stopped"
                            | "DNS unavailable"
                            | "Connection could not be verified"
                            | "Redirect stopped"
                            | "Inspection stopped"
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
                    if let Ok(lookup) = browser_relay::certificate_history::prepare(&name) {
                        history_result
                            .set_text(&format!("Opt-in · initial hostname: {}", lookup.host));
                        history_lookup(
                            &history,
                            lookup,
                            &history_result,
                            &log,
                            &cancel,
                            crate::ct_transport::history,
                        );
                    }
                    reputation(
                        &reputation_button,
                        &name,
                        &reputation_result,
                        browser.clone(),
                    );
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
                    risk_view.finish(false);
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
                    risk_view.resume();
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
                Ok(Event::Risk {
                    facts,
                    factors,
                    lookalikes,
                }) => {
                    let mut latest = last_facts.lock().unwrap();
                    *latest = (latest.0 + 1, Some(facts));
                    drop(latest);
                    risk_view.update(factors, lookalikes);
                }
                Ok(Event::Done) => {
                    done.set(true);
                    risk_view.finish(route_complete);
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
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if changed {
                        peer_view.render(peers.borrow().get(selected.get()), done.get());
                    }
                    return glib::ControlFlow::Continue;
                }
                Err(_) => {
                    spinner.stop();
                    status.set_text("Checks stopped");
                    risk_view.finish(false);
                    return glib::ControlFlow::Break;
                }
            }
            changed = true;
        }
    });
    popup.present();
    GtkWindowExt::set_focus(&popup, None::<&gtk::Widget>);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expander_ui_carries_an_escaped_accessible_label() {
        let ui = expander_ui("Warning: a<b> & \"c\"");
        assert!(ui.contains(
            "<property name=\"label\">Warning: a&lt;b&gt; &amp; &quot;c&quot;</property>"
        ));
        assert!(ui.contains("class=\"GtkExpander\""));
    }

    #[test]
    #[ignore = "GTK regression: run under Xvfb with --test-threads=1"]
    fn ping_requires_confirmation_for_each_peer() {
        gtk::init().unwrap();
        let button = menu("Ping…");
        let window = gtk::Window::new();
        window.set_child(Some(&button));
        window.present();
        let peers = Rc::new(RefCell::new(Vec::new()));
        let names = gtk::StringList::new(&[]);
        let first = "127.0.0.1".parse().unwrap();
        let second = "127.0.0.2".parse().unwrap();
        add_peer(&peers, &names, first);
        add_peer(&peers, &names, second);
        let (sender, receiver) = mpsc::channel();
        // Cancelled transport ensures this consent test never sends packets.
        let cancel = Arc::new(AtomicBool::new(true));
        for ip in [first, second] {
            ping_consent(&button, ip, &sender, &cancel, &peers);
            button.popup();
            while glib::MainContext::default().iteration(false) {}
            assert!(
                receiver.try_recv().is_err(),
                "opening or changing peers must not ping"
            );
        }
        let content = button.popover().unwrap().child().unwrap();
        let mut widget = content.first_child();
        let mut confirmed = false;
        while let Some(child) = widget {
            if let Ok(confirm) = child.clone().downcast::<gtk::Button>() {
                confirm.emit_clicked();
                confirmed = true;
                break;
            }
            widget = child.next_sibling();
        }
        assert!(confirmed);
        assert!(matches!(receiver.try_recv(), Ok(Event::PingStarted(ip)) if ip == second));
        assert!(!peers.borrow()[0].ping_running);
        assert!(peers.borrow()[1].ping_running);
        window.destroy();
    }

    #[test]
    #[ignore = "GTK regression: run under Xvfb with --test-threads=1"]
    fn rebuilding_risk_rows_keeps_focus_and_expansion() {
        use browser_relay::risk::{Factor, Severity};
        gtk::init().unwrap();
        let factor = |id, title: &str| Factor {
            id,
            severity: Severity::Notice,
            title: title.into(),
            evidence: "Evidence.".into(),
            compare: None,
        };
        let rows = gtk::Box::new(gtk::Orientation::Vertical, 2);
        let view = RiskView {
            disclosure: gtk::Expander::new(None),
            available: Rc::new(Cell::new(true)),
            summary: text("", "dashboard-value"),
            rows: rows.clone(),
            missing: gtk::Box::new(gtk::Orientation::Horizontal, 0),
            shield: gtk::Image::new(),
            factors: Rc::new(RefCell::new(Vec::new())),
            finished: Rc::new(Cell::new(false)),
            complete: Rc::new(Cell::new(false)),
        };
        let window = gtk::Window::new();
        window.set_child(Some(&rows));
        window.present();
        view.update(vec![factor("a", "First"), factor("b", "Second")], true);
        let second = rows.last_child().unwrap();
        second
            .downcast_ref::<gtk::Expander>()
            .unwrap()
            .set_expanded(true);
        assert!(second.grab_focus());
        view.update(
            vec![
                factor("a", "First"),
                factor("b", "Second"),
                factor("c", "Third"),
            ],
            true,
        );
        let rebuilt = rows.first_child().unwrap().next_sibling().unwrap();
        assert_ne!(rebuilt, second, "rows are rebuilt");
        assert!(
            rebuilt
                .downcast_ref::<gtk::Expander>()
                .unwrap()
                .is_expanded()
        );
        let focus = GtkWindowExt::focus(&window).expect("focus kept");
        assert!(focus == rebuilt || focus.is_ancestor(&rebuilt));
        assert!(!view.disclosure.is_expanded(), "notices stay compact");
        let mut warning = factor("warning", "Lookalike");
        warning.severity = Severity::Warning;
        view.update(vec![warning.clone()], true);
        assert!(
            view.disclosure.is_expanded(),
            "new warnings open the evidence"
        );
        view.disclosure.set_expanded(false);
        view.update(vec![warning.clone()], true);
        assert!(
            !view.disclosure.is_expanded(),
            "repeated results respect a manual collapse"
        );
        warning.title = "Another lookalike".into();
        view.update(vec![warning], true);
        assert!(
            view.disclosure.is_expanded(),
            "a new warning remains visible"
        );
        window.destroy();
    }

    #[test]
    fn severity_is_never_colour_alone() {
        use browser_relay::risk::Severity;
        for severity in [Severity::Warning, Severity::Caution, Severity::Notice] {
            let (icon, class) = severity_style(severity);
            assert!(icon.ends_with("-symbolic"));
            assert!(class.starts_with("risk-"));
            assert!(!severity.word().is_empty());
        }
    }

    #[test]
    fn comparison_highlights_only_the_difference_and_escapes_markup() {
        let markup = comparison_markup("paypa1.com", "paypal.com");
        assert!(markup.contains("paypa<span"));
        assert!(markup.contains(">1</span>.com"));
        assert!(markup.contains(">l</span>.com"));
        assert!(markup.starts_with("This link   "));
        let hostile = comparison_markup("a<b>.com", "a&b.com");
        assert!(
            !hostile.contains("<b>") && hostile.contains("&lt;b&gt;") && hostile.contains("&amp;")
        );
        gtk::pango::parse_markup(&hostile, '\0').expect("valid Pango markup");
    }
    #[test]
    #[ignore = "GTK PATH fallback fixture: set RELAY_BROWSER_CAPTURE and prepend a fake chromium to PATH"]
    fn reputation_without_discovery_uses_path_browser() {
        let capture = std::env::var_os("RELAY_BROWSER_CAPTURE")
            .expect("Requires an isolated fake browser fixture");
        // The explicit fixture requirement prevents ever opening a real browser.
        let program = crate::relay::executable(&["chromium"]).unwrap();
        assert_eq!(program.parent(), std::path::Path::new(&capture).parent());
        gtk::init().unwrap();
        let button = menu("VirusTotal");
        let status = text("Opt-in", "list-note");
        let (_, browser, failed) = glib::MainContext::default()
            .block_on(gtk::gio::spawn_blocking(|| {
                crate::ui::discover_for_ui(|| panic!("discovery fixture failed"))
            }))
            .unwrap();
        assert!(failed);
        reputation(&button, "example.org", &status, browser);
        let content = button.popover().unwrap().child().unwrap();
        let confirm = content
            .last_child()
            .unwrap()
            .downcast::<gtk::Button>()
            .unwrap();
        assert_eq!(confirm.label().as_deref(), Some("Open in Chromium ↗"));
        assert!(confirm.is_sensitive());
        confirm.emit_clicked();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while status.text() != "Opened in browser" && std::time::Instant::now() < deadline {
            while glib::MainContext::default().iteration(false) {}
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(status.text(), "Opened in browser");
        assert_eq!(
            std::fs::read(capture).unwrap(),
            b"--\0https://www.virustotal.com/gui/domain/example.org\0"
        );
    }

    #[test]
    #[ignore = "GTK regression: run under Xvfb with --test-threads=1"]
    fn certificate_history_waits_for_explicit_confirmation() {
        gtk::init().unwrap();
        let button = menu("Certificate history…");
        let window = gtk::Window::new();
        window.set_child(Some(&button));
        window.present();
        let output = text("Not checked", "footer");
        let log = gtk::TextBuffer::new(None::<&gtk::TextTagTable>);
        let cancel = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let called = calls.clone();
        let lookup = browser_relay::certificate_history::prepare("github.com").unwrap();
        history_lookup(
            &button,
            lookup,
            &output,
            &log,
            &cancel,
            move |_, after, key, _| {
                let page = called.fetch_add(1, Ordering::Relaxed);
                assert_eq!(after, if page == 0 { None } else { Some("next-cursor") });
                assert_eq!(key, "fixture-key");
                Ok(browser_relay::certificate_history::Page {
                    summary: format!("Fixture page {}", page + 1),
                    next: if page == 0 {
                        Some("next-cursor".into())
                    } else {
                        None
                    },
                })
            },
        );
        button.popup();
        while glib::MainContext::default().iteration(false) {}
        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "opening disclosure must not contact the provider"
        );
        let content = button.popover().unwrap().child().unwrap();
        let mut child = content.first_child();
        let mut action = None;
        while let Some(widget) = child {
            if let Ok(key) = widget.clone().downcast::<gtk::PasswordEntry>() {
                key.set_text("fixture-key");
            }
            if let Ok(confirm) = widget.clone().downcast::<gtk::Button>() {
                action = Some(confirm);
            }
            child = widget.next_sibling();
        }
        let confirm = action.unwrap();
        for page in 1..=2 {
            assert_eq!(
                calls.load(Ordering::Relaxed),
                page - 1,
                "pagination must wait for another click"
            );
            confirm.emit_clicked();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while output.text() != format!("Fixture page {page}")
                && std::time::Instant::now() < deadline
            {
                while glib::MainContext::default().iteration(false) {}
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(calls.load(Ordering::Relaxed), page);
            assert_eq!(output.text(), format!("Fixture page {page}"));
        }
        assert!(!confirm.is_sensitive());
        assert!(
            !log.text(&log.start_iter(), &log.end_iter(), false)
                .contains("fixture-key")
        );
        window.destroy();
    }

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
