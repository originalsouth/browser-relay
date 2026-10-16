use crate::Result;
use crate::relay::{Action, execute_gui};
use gtk::{gdk, gio, glib, pango, prelude::*};
use std::{cell::Cell, rc::Rc, time::Duration};

fn label(text: &str, class: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.set_xalign(0.0);
    label.add_css_class(class);
    label
}

fn icon() -> Result<gtk::Image> {
    let stream = gio::MemoryInputStream::from_bytes(&glib::Bytes::from_static(include_bytes!(
        "../assets/browser-relay.svg"
    )));
    let pixbuf = gtk::gdk_pixbuf::Pixbuf::from_stream_at_scale(
        &stream,
        96,
        96,
        true,
        gio::Cancellable::NONE,
    )
    .map_err(|e| format!("Could not load the app icon: {e}"))?;
    let image = gtk::Image::from_paintable(Some(&gdk::Texture::for_pixbuf(&pixbuf)));
    image.set_pixel_size(44);
    Ok(image)
}

fn destination(url: &str) -> String {
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    {
        // Strip user information so it cannot impersonate the destination host.
        rest.split(['/', '?', '#'])
            .next()
            .unwrap_or(rest)
            .rsplit('@')
            .next()
            .unwrap_or(rest)
            .to_string()
    } else if url.starts_with("file:") || url.starts_with('/') {
        "Local file".into()
    } else {
        "Link destination".into()
    }
}

fn qr_panel(code: Option<qrcode::QrCode>) -> gtk::Box {
    let panel = gtk::Box::new(gtk::Orientation::Vertical, 8);
    panel.set_valign(gtk::Align::Center);
    panel.set_halign(gtk::Align::End);
    panel.set_hexpand(false);
    if let Some(code) = code {
        panel.add_css_class("qr-code");
        panel.set_tooltip_text(Some("Scan with another device's camera to open this link"));
        let drawing = gtk::DrawingArea::builder()
            .content_width(crate::qr::SIDE)
            .content_height(crate::qr::SIDE)
            .build();
        drawing.set_draw_func(move |_, cr, width, height| {
            cr.set_antialias(gtk::cairo::Antialias::None);
            cr.set_source_rgb(1.0, 1.0, 1.0);
            let _ = cr.paint();
            let modules = code.width() + 2 * crate::qr::QUIET_ZONE;
            let scale = width.min(height) / modules as i32;
            if scale < 1 {
                return;
            }
            let offset_x = (width - code.width() as i32 * scale) / 2;
            let offset_y = (height - code.width() as i32 * scale) / 2;
            cr.set_source_rgb(0.0, 0.0, 0.0);
            for y in 0..code.width() {
                for x in 0..code.width() {
                    if code[(x, y)] == qrcode::Color::Dark {
                        cr.rectangle(
                            f64::from(offset_x + x as i32 * scale),
                            f64::from(offset_y + y as i32 * scale),
                            f64::from(scale),
                            f64::from(scale),
                        );
                    }
                }
            }
            let _ = cr.fill();
        });
        panel.append(&drawing);
    } else {
        panel.add_css_class("qr-warning");
        panel.set_size_request(crate::qr::SIDE + 8, crate::qr::SIDE + 8);
        let content = gtk::Box::new(gtk::Orientation::Vertical, 9);
        content.set_valign(gtk::Align::Center);
        content.set_vexpand(true);
        let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
        icon.set_pixel_size(26);
        content.append(&icon);
        let title = label("Link too long for QR", "qr-warning-title");
        title.set_xalign(0.5);
        content.append(&title);
        let hint = label(
            "Copy the link to
share it instead.",
            "qr-warning-hint",
        );
        hint.set_justify(gtk::Justification::Center);
        hint.set_xalign(0.5);
        content.append(&hint);
        panel.append(&content);
    }
    panel
}

fn route_button(
    title: &str,
    description: &str,
    icon_name: &str,
    key: &str,
    utility: bool,
) -> gtk::Button {
    let button = gtk::Button::new();
    button.add_css_class("route");
    button.set_cursor_from_name(Some("pointer"));
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    let image = gio::Icon::for_string(icon_name)
        .map(|icon| gtk::Image::from_gicon(&icon))
        .unwrap_or_else(|_| gtk::Image::from_icon_name("web-browser-symbolic"));
    image.set_pixel_size(32);
    if utility {
        image.add_css_class("copy-icon");
    }
    row.append(&image);
    let text = gtk::Box::new(gtk::Orientation::Vertical, 3);
    text.set_hexpand(true);
    let title_label = label(title, "route-title");
    title_label.set_ellipsize(pango::EllipsizeMode::End);
    title_label.set_max_width_chars(25);
    text.append(&title_label);
    let description_label = label(description, "route-description");
    description_label.set_ellipsize(pango::EllipsizeMode::End);
    description_label.set_max_width_chars(34);
    text.append(&description_label);
    button.set_tooltip_text(Some(title));
    row.append(&text);
    let shortcut = label(key, "key");
    shortcut.set_valign(gtk::Align::Center);
    if !key.is_empty() {
        row.append(&shortcut);
    }
    button.set_child(Some(&row));
    button
}

fn show_qr(parent: &gtk::Window, link: &str, multiple: bool) {
    // Generate and render only after the user explicitly requests it.
    let code = crate::qr::encode(link);
    let available = code.is_some();
    let popup = gtk::Window::builder()
        .title("Link QR code")
        .transient_for(parent)
        .modal(true)
        .destroy_with_parent(true)
        .default_width(280)
        .resizable(false)
        .icon_name("browser-relay")
        .build();
    popup.add_css_class("relay");
    let header = gtk::HeaderBar::new();
    header.set_decoration_layout(Some(":close"));
    header.set_title_widget(Some(&label("QR code", "brand")));
    popup.set_titlebar(Some(&header));
    let body = gtk::Box::new(gtk::Orientation::Vertical, 14);
    body.set_margin_start(24);
    body.set_margin_end(24);
    body.set_margin_top(12);
    body.set_margin_bottom(24);
    let title = label(&destination(link), "destination");
    title.set_xalign(0.5);
    title.set_ellipsize(pango::EllipsizeMode::End);
    title.set_max_width_chars(26);
    body.append(&title);
    let panel = qr_panel(code);
    panel.set_halign(gtk::Align::Center);
    body.append(&panel);
    if available {
        let caption = label(
            if multiple {
                "Scan to open the first link"
            } else {
                "Scan to open on your phone"
            },
            "qr-caption",
        );
        caption.set_xalign(0.5);
        body.append(&caption);
    }
    let close = gtk::Button::with_label("Hide QR code");
    close.add_css_class("route");
    let weak_popup = popup.downgrade();
    close.connect_clicked(move |_| {
        if let Some(popup) = weak_popup.upgrade() {
            popup.close();
        }
    });
    body.append(&close);
    popup.set_child(Some(&body));
    let keys = gtk::EventControllerKey::new();
    let weak_popup = popup.downgrade();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            if let Some(popup) = weak_popup.upgrade() {
                popup.close();
            }
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    popup.add_controller(keys);
    popup.present();
    close.grab_focus();
}

fn initialize() -> Result<()> {
    if gtk::is_initialized() {
        return Ok(());
    }
    glib::set_prgname(Some("browser-relay"));
    glib::set_application_name("Browser Relay");
    gtk::init().map_err(|e| format!("Could not open the desktop chooser: {e}. Try --terminal."))?;
    let display = gdk::Display::default().ok_or("No desktop display available")?;
    let css = gtk::CssProvider::new();
    css.load_from_data(include_str!("../assets/style.css"));
    gtk::style_context_add_provider_for_display(
        &display,
        &css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    Ok(())
}

fn content_height(monitor_height: i32) -> i32 {
    monitor_height.saturating_sub(120).clamp(1, 960)
}

fn window() -> (gtk::Window, gtk::Box, glib::MainLoop, Rc<Cell<bool>>) {
    let busy = Rc::new(Cell::new(false));
    let main_loop = glib::MainLoop::new(None, false);
    let window = gtk::Window::builder()
        .title("Browser Relay")
        .default_width(460)
        .resizable(false)
        .icon_name("browser-relay")
        .build();
    window.add_css_class("relay");
    let header = gtk::HeaderBar::new();
    header.set_decoration_layout(Some(":close"));
    header.set_title_widget(Some(&gtk::Box::new(gtk::Orientation::Horizontal, 0)));
    window.set_titlebar(Some(&header));
    let body = gtk::Box::new(gtk::Orientation::Vertical, 0);
    body.set_margin_start(28);
    body.set_margin_end(28);
    body.set_margin_top(2);
    body.set_margin_bottom(24);
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .propagate_natural_height(true)
        .max_content_height(640)
        .child(&body)
        .build();
    window.set_child(Some(&scroll));
    // The compositor chooses placement. Query the mapped surface, then track
    // monitor crossings rather than assuming monitor zero is the destination.
    let weak_scroll = scroll.downgrade();
    let update = move |surface: &gdk::Surface| {
        if let (Some(scroll), Some(monitor)) = (
            weak_scroll.upgrade(),
            surface.display().monitor_at_surface(surface),
        ) {
            scroll.set_max_content_height(content_height(monitor.geometry().height()));
        }
    };
    let on_realize = update.clone();
    window.connect_realize(move |window| {
        let Some(surface) = window.surface() else {
            return;
        };
        on_realize(&surface);
        let on_enter = on_realize.clone();
        surface.connect_enter_monitor(move |surface, _| on_enter(surface));
        let on_leave = on_realize.clone();
        surface.connect_leave_monitor(move |surface, _| on_leave(surface));
    });
    window.connect_map(move |window| {
        if let Some(surface) = window.surface() {
            update(&surface);
        }
    });
    let loop_clone = main_loop.clone();
    let closing_busy = busy.clone();
    window.connect_close_request(move |_| {
        if closing_busy.get() {
            return glib::Propagation::Stop;
        }
        loop_clone.quit();
        glib::Propagation::Proceed
    });
    let keys = gtk::EventControllerKey::new();
    let weak_window = window.downgrade();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            if let Some(window) = weak_window.upgrade() {
                window.close();
            }
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    window.add_controller(keys);
    (window, body, main_loop, busy)
}

fn shortcut(index: usize, fallback: &str) -> String {
    if index < 9 {
        (index + 1).to_string()
    } else {
        fallback.into()
    }
}

pub fn run(urls: &[String]) -> Result<()> {
    run_with_discovery(urls, || {
        let browsers = crate::browser::discover();
        let preferred = crate::browser::preferred(&browsers);
        (browsers, preferred)
    })
}

fn run_with_discovery(
    urls: &[String],
    discover: impl FnOnce() -> (
        Vec<crate::browser::Browser>,
        Option<crate::browser::Browser>,
    ) + Send
    + 'static,
) -> Result<()> {
    initialize()?;
    let (window, body, main_loop, busy) = window();
    let brand = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    brand.append(&icon()?);
    brand.append(&label("Browser Relay", "brand"));
    body.append(&brand);
    let heading = label(
        if urls.len() == 1 {
            "Where to?"
        } else {
            "Send them somewhere."
        },
        "heading",
    );
    heading.set_margin_top(23);
    body.append(&heading);
    let subtitle = label(
        if urls.len() == 1 {
            "A little choice before your next click."
        } else {
            "Choose one destination for all your links."
        },
        "subtitle",
    );
    subtitle.set_margin_top(5);
    body.append(&subtitle);

    let preview = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    preview.add_css_class("preview");
    preview.set_margin_top(21);
    preview.set_margin_bottom(22);
    let link = gtk::Image::from_icon_name("insert-link-symbolic");
    link.add_css_class("preview-icon");
    link.set_pixel_size(20);
    preview.append(&link);
    let details = gtk::Box::new(gtk::Orientation::Vertical, 6);
    details.set_hexpand(true);
    details.set_valign(gtk::Align::Center);
    let title = if urls.len() > 1 {
        format!("{} links · {}", urls.len(), destination(&urls[0]))
    } else {
        destination(&urls[0])
    };
    let host = label(&title, "destination");
    host.set_ellipsize(pango::EllipsizeMode::End);
    host.set_max_width_chars(38);
    details.append(&host);
    let url = label(&urls[0], "url");
    url.set_ellipsize(pango::EllipsizeMode::Middle);
    url.set_max_width_chars(44);
    url.set_tooltip_text(Some(&urls.join("\n")));
    details.append(&url);
    preview.append(&details);
    body.append(&preview);
    let eyebrow = label("OPEN WITH", "eyebrow");
    eyebrow.set_margin_bottom(10);
    body.append(&eyebrow);

    let loading = label("Finding browsers…", "footer");
    body.append(&loading);
    let cancel = gtk::EventControllerKey::new();
    let weak_window = window.downgrade();
    let cancel_busy = busy.clone();
    cancel.connect_key_pressed(move |_, key, _, modifiers| {
        if matches!(key, gdk::Key::q | gdk::Key::Q)
            && !cancel_busy.get()
            && !modifiers.intersects(
                gdk::ModifierType::CONTROL_MASK
                    | gdk::ModifierType::ALT_MASK
                    | gdk::ModifierType::SUPER_MASK,
            )
        {
            if let Some(window) = weak_window.upgrade() {
                window.close();
            }
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    window.add_controller(cancel);
    let weak_window = window.downgrade();
    let urls = urls.to_vec();
    glib::MainContext::default().spawn_local(async move {
        let discovered = gio::spawn_blocking(move || discover_for_ui(discover)).await;
        let Some(window) = weak_window.upgrade().filter(|w| w.is_visible()) else {
            return;
        };
        match discovered {
            Ok((browsers, preferred, failed)) => {
                if failed {
                    loading
                        .set_text("Browser discovery failed · other actions are available below");
                } else {
                    body.remove(&loading);
                }
                populate(&window, &body, &urls, browsers, preferred, busy);
            }
            Err(_) => {
                loading.set_text("Browser discovery failed · other actions are available below");
                populate(&window, &body, &urls, Vec::new(), None, busy);
            }
        }
    });
    window.present();
    main_loop.run();
    Ok(())
}

pub(crate) fn discover_for_ui(
    discover: impl FnOnce() -> (
        Vec<crate::browser::Browser>,
        Option<crate::browser::Browser>,
    ),
) -> (
    Vec<crate::browser::Browser>,
    Option<crate::browser::Browser>,
    bool,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(discover));
    let failed = result.is_err();
    let (browsers, preferred) = result.unwrap_or_default();
    (
        browsers,
        preferred.or_else(crate::browser::fallback),
        failed,
    )
}

fn populate(
    window: &gtk::Window,
    body: &gtk::Box,
    urls: &[String],
    browsers: Vec<crate::browser::Browser>,
    inspection_browser: Option<crate::browser::Browser>,
    busy: Rc<Cell<bool>>,
) {
    let routes = gtk::Box::new(gtk::Orientation::Vertical, 9);
    let status = label(
        "Ctrl+C copy · Ctrl+R QR · Ctrl+I inspect · Q/Esc dismiss",
        "footer",
    );
    status.set_margin_top(19);
    status.set_wrap(true);
    status.set_max_width_chars(48);
    if browsers.is_empty() {
        let empty = label(
            "No browsers found · Copy or scan the link below",
            "subtitle",
        );
        empty.set_wrap(true);
        routes.append(&empty);
    }
    let mut choices: Vec<_> = browsers
        .into_iter()
        .map(|browser| {
            let name = browser.name.clone();
            let icon = browser.icon.clone();
            (
                Action::Browser(browser),
                name.clone(),
                format!("Open in {name}"),
                icon,
            )
        })
        .collect();
    choices.push((
        Action::Copy,
        if urls.len() > 1 {
            "Copy links"
        } else {
            "Copy link"
        }
        .into(),
        "Keep it on your clipboard".into(),
        "edit-copy-symbolic".into(),
    ));
    let copy_index = choices.len() - 1;
    let mut buttons = Vec::new();
    for (index, (action, title, description, icon_name)) in choices.into_iter().enumerate() {
        let key = shortcut(index, if action == Action::Copy { "Ctrl+C" } else { "" });
        let button = route_button(
            &title,
            &description,
            &icon_name,
            &key,
            action == Action::Copy,
        );
        routes.append(&button);
        let busy = busy.clone();
        let routes = routes.downgrade();
        let status = status.downgrade();
        let window = window.downgrade();
        let urls = urls.to_vec();
        button.connect_clicked(move |_| {
            let (Some(routes), Some(status), Some(window)) =
                (routes.upgrade(), status.upgrade(), window.upgrade())
            else {
                return;
            };
            if busy.replace(true) {
                return;
            }
            routes.set_sensitive(false);
            status.remove_css_class("error");
            status.set_text(if action == Action::Copy {
                "Copying…"
            } else {
                "Opening…"
            });
            let urls = urls.clone();
            let action = action.clone();
            let copied = action == Action::Copy;
            let busy = busy.clone();
            glib::MainContext::default().spawn_local(async move {
                let result = execute_gui(action, urls).await;
                match result {
                    Ok(()) => {
                        status.add_css_class("success");
                        status.set_text(if copied {
                            "✓ Copied to clipboard"
                        } else {
                            "✓ Opening in your browser"
                        });
                        let window = window.clone();
                        glib::timeout_add_local_once(
                            Duration::from_millis(if copied { 750 } else { 200 }),
                            move || {
                                busy.set(false);
                                window.close();
                            },
                        );
                    }
                    Err(error) => {
                        status.set_text(&error);
                        status.add_css_class("error");
                        routes.set_sensitive(true);
                        busy.set(false);
                    }
                }
            });
        });
        buttons.push(button);
    }
    let qr_button = route_button(
        "Show QR code",
        "Reveal for another device",
        "camera-photo-symbolic",
        &shortcut(copy_index + 1, "Ctrl+R"),
        true,
    );
    let weak_window = window.downgrade();
    let qr_link = urls[0].clone();
    let multiple = urls.len() > 1;
    qr_button.connect_clicked(move |_| {
        if let Some(window) = weak_window.upgrade() {
            show_qr(&window, &qr_link, multiple);
        }
    });
    routes.append(&qr_button);
    buttons.push(qr_button);
    let inspect_button = route_button(
        "Inspect link",
        "Contacts this URL · checks connection & lists",
        "security-high-symbolic",
        &shortcut(copy_index + 2, "Ctrl+I"),
        true,
    );
    inspect_button.set_tooltip_text(Some(
        "Contacts the destination to check its connection; online reputation lookups are optional",
    ));
    let weak_window = window.downgrade();
    let inspect_link = urls[0].clone();
    inspect_button.connect_clicked(move |_| {
        if let Some(window) = weak_window.upgrade() {
            crate::inspector_ui::show(&window, &inspect_link, multiple, inspection_browser.clone());
        }
    });
    routes.append(&inspect_button);
    buttons.push(inspect_button);
    body.append(&routes);
    body.append(&status);
    let keys = gtk::EventControllerKey::new();
    keys.connect_key_pressed(move |_, key, _, modifiers| {
        if modifiers.intersects(gdk::ModifierType::ALT_MASK | gdk::ModifierType::SUPER_MASK) {
            return glib::Propagation::Proceed;
        }
        let index = if modifiers.contains(gdk::ModifierType::CONTROL_MASK) {
            match key {
                gdk::Key::c | gdk::Key::C => Some(copy_index),
                gdk::Key::r | gdk::Key::R => Some(copy_index + 1),
                gdk::Key::i | gdk::Key::I => Some(copy_index + 2),
                _ => None,
            }
        } else {
            match key {
                gdk::Key::_1 | gdk::Key::KP_1 => Some(0),
                gdk::Key::_2 | gdk::Key::KP_2 => Some(1),
                gdk::Key::_3 | gdk::Key::KP_3 => Some(2),
                gdk::Key::_4 | gdk::Key::KP_4 => Some(3),
                gdk::Key::_5 | gdk::Key::KP_5 => Some(4),
                gdk::Key::_6 | gdk::Key::KP_6 => Some(5),
                gdk::Key::_7 | gdk::Key::KP_7 => Some(6),
                gdk::Key::_8 | gdk::Key::KP_8 => Some(7),
                gdk::Key::_9 | gdk::Key::KP_9 => Some(8),
                _ => None,
            }
        };
        if let Some(button) = index.and_then(|i| buttons.get(i)) {
            if button.is_sensitive() {
                button.emit_clicked();
            }
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    window.add_controller(keys);
}

/// Desktop launchers have no URL; ask for one before displaying the chooser.
pub fn prompt() -> Result<Option<String>> {
    initialize()?;
    let (window, body, main_loop, _) = window();
    let result = Rc::new(std::cell::RefCell::new(None));
    body.set_spacing(16);
    body.set_margin_start(24);
    body.set_margin_end(24);
    body.set_margin_top(24);
    let image = icon()?;
    image.set_halign(gtk::Align::Start);
    body.append(&image);
    body.append(&label("Got a link?", "heading"));
    body.append(&label(
        "Paste it here, then choose where it goes.",
        "subtitle",
    ));
    let entry = gtk::Entry::builder()
        .placeholder_text("https://example.com")
        .hexpand(true)
        .build();
    entry.add_css_class("preview");
    body.append(&entry);
    let next = gtk::Button::with_label("Choose destination →");
    next.add_css_class("route");
    next.set_sensitive(false);
    let weak_next = next.downgrade();
    entry.connect_changed(move |entry| {
        if let Some(next) = weak_next.upgrade() {
            next.set_sensitive(crate::validate_link(entry.text().trim()).is_ok());
        }
    });
    let result_clone = result.clone();
    let weak_window = window.downgrade();
    let entry_clone = entry.clone();
    next.connect_clicked(move |_| {
        let link = entry_clone.text().trim().to_string();
        if crate::validate_link(&link).is_ok() {
            *result_clone.borrow_mut() = Some(link);
            if let Some(window) = weak_window.upgrade() {
                window.close();
            }
        }
    });
    let weak_next = next.downgrade();
    entry.connect_activate(move |_| {
        if let Some(next) = weak_next.upgrade()
            && next.is_sensitive()
        {
            next.emit_clicked();
        }
    });
    body.append(&next);
    window.present();
    entry.grab_focus();
    main_loop.run();
    Ok(result.take())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "GTK regression: run under Xvfb with --test-threads=1"]
    fn busy_dismissal_and_browser_icon_style() {
        initialize().unwrap();
        let (window, _, _, busy) = window();
        window.present();
        busy.set(true);
        window.close();
        assert!(
            window.is_visible(),
            "Pending action must survive a window close"
        );
        busy.set(false);
        window.close();
        assert!(!window.is_visible());
        for (utility, expected) in [(false, false), (true, true)] {
            let button = route_button("Test", "", "web-browser-symbolic", "1", utility);
            let image = button.child().unwrap().first_child().unwrap();
            assert_eq!(image.has_css_class("copy-icon"), expected);
        }
    }

    #[test]
    #[ignore = "GTK regression: run under Xvfb with --test-threads=1"]
    fn discovery_failure_keeps_copy_qr_and_inspect() {
        initialize().unwrap();
        fn labels(widget: &gtk::Widget, result: &mut Vec<String>) {
            if let Some(label) = widget.downcast_ref::<gtk::Label>() {
                result.push(label.text().to_string());
            }
            let mut child = widget.first_child();
            while let Some(widget) = child {
                labels(&widget, result);
                child = widget.next_sibling();
            }
        }
        let found = Rc::new(Cell::new(false));
        let found_tick = found.clone();
        let correct_monitor = Rc::new(Cell::new(false));
        let monitor_tick = correct_monitor.clone();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        glib::timeout_add_local(Duration::from_millis(20), move || {
            let windows = gtk::Window::toplevels();
            for i in 0..windows.n_items() {
                if let Some(window) = windows.item(i).and_downcast::<gtk::Window>()
                    && window.title().as_deref() == Some("Browser Relay")
                {
                    let mut text = Vec::new();
                    labels(window.upcast_ref(), &mut text);
                    let actions = ["Copy link", "Show QR code", "Inspect link"];
                    let ready = actions.iter().all(|label| text.iter().any(|s| s == label));
                    if ready || std::time::Instant::now() >= deadline {
                        found_tick.set(ready);
                        if let (Some(surface), Some(scroll)) = (
                            window.surface(),
                            window.child().and_downcast::<gtk::ScrolledWindow>(),
                        ) && let Some(monitor) = surface.display().monitor_at_surface(&surface)
                        {
                            monitor_tick.set(
                                scroll.max_content_height()
                                    == content_height(monitor.geometry().height()),
                            );
                        }
                        window.close();
                        return glib::ControlFlow::Break;
                    }
                }
            }
            glib::ControlFlow::Continue
        });
        run_with_discovery(
            &["https://github.com/originalsouth/browser-relay".into()],
            || panic!("discovery fixture failed"),
        )
        .unwrap();
        assert!(
            found.get(),
            "Discovery failure removed browser-independent actions"
        );
        assert!(
            correct_monitor.get(),
            "Content limit must follow the window's surface monitor"
        );
    }

    #[test]
    #[ignore = "GTK regression: run under Xvfb with --test-threads=1"]
    fn slow_discovery_does_not_block_cancellation() {
        initialize().unwrap();
        let gate = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let worker_gate = gate.clone();
        let closed = Rc::new(Cell::new(false));
        let closed_tick = closed.clone();
        glib::timeout_add_local_once(Duration::from_millis(150), move || {
            let windows = gtk::Window::toplevels();
            for i in 0..windows.n_items() {
                if let Some(window) = windows.item(i).and_downcast::<gtk::Window>()
                    && window.title().as_deref() == Some("Browser Relay")
                {
                    assert!(window.is_visible());
                    closed_tick.set(true);
                    window.close();
                }
            }
        });
        let start = std::time::Instant::now();
        run_with_discovery(
            &["https://github.com/originalsouth/browser-relay".into()],
            move || {
                let (lock, ready) = &*worker_gate;
                let _ = ready
                    .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(3), |released| {
                        !*released
                    })
                    .unwrap();
                (Vec::new(), None)
            },
        )
        .unwrap();
        *gate.0.lock().unwrap() = true;
        gate.1.notify_one();
        assert!(closed.get());
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "Discovery blocked the GTK loop"
        );
    }

    #[test]
    #[ignore = "GTK theme regression: run under Xvfb with G_DEBUG=fatal-warnings"]
    fn scrollbars_have_valid_geometry() {
        initialize().unwrap();
        let content = gtk::DrawingArea::new();
        content.set_content_width(900);
        content.set_content_height(900);
        let scroll = gtk::ScrolledWindow::builder().child(&content).build();
        let window = gtk::Window::builder()
            .default_width(300)
            .default_height(240)
            .child(&scroll)
            .build();
        window.add_css_class("relay");
        window.present();
        let settle = || {
            let until = std::time::Instant::now() + Duration::from_millis(180);
            while std::time::Instant::now() < until {
                while glib::MainContext::default().iteration(false) {}
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        for overlay in [true, false] {
            scroll.set_overlay_scrolling(overlay);
            settle();
            for bar in [scroll.hscrollbar(), scroll.vscrollbar()] {
                for flags in [
                    gtk::StateFlags::NORMAL,
                    gtk::StateFlags::PRELIGHT,
                    gtk::StateFlags::ACTIVE,
                    gtk::StateFlags::BACKDROP,
                ] {
                    bar.set_state_flags(flags, true);
                    settle();
                    for axis in [gtk::Orientation::Horizontal, gtk::Orientation::Vertical] {
                        let (min, natural, _, _) = bar.measure(axis, -1);
                        assert!(
                            min > 0 && natural >= min,
                            "Scrollbar must retain usable geometry"
                        );
                    }
                }
            }
            for adjustment in [scroll.hadjustment(), scroll.vadjustment()] {
                assert!(adjustment.upper() > adjustment.page_size());
                adjustment.set_value(100.0);
                assert_eq!(adjustment.value(), 100.0);
            }
        }
        content.set_content_width(10);
        content.set_content_height(10);
        settle();
        assert!(!scroll.hscrollbar().is_child_visible());
        assert!(!scroll.vscrollbar().is_child_visible());
        window.close();
    }

    #[test]
    fn preview_shows_actual_host_not_userinfo() {
        assert_eq!(
            destination("https://trusted.example@actual.example/path?q=1"),
            "actual.example"
        );
        assert_eq!(destination("https://example.org?query"), "example.org");
        assert_eq!(destination("file:///tmp/test.html"), "Local file");
    }
}
