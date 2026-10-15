use crate::Result;
use crate::relay::{Action, executable, execute};
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
    available: bool,
) -> gtk::Button {
    let button = gtk::Button::new();
    button.add_css_class("route");
    button.set_sensitive(available);
    button.set_cursor_from_name(Some("pointer"));
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    let image = gtk::Image::from_icon_name(icon_name);
    image.set_pixel_size(32);
    if matches!(key, "3" | "4" | "5") {
        image.add_css_class("copy-icon");
    }
    row.append(&image);
    let text = gtk::Box::new(gtk::Orientation::Vertical, 3);
    text.set_hexpand(true);
    text.append(&label(title, "route-title"));
    text.append(&label(
        if available {
            description
        } else {
            "Not installed"
        },
        "route-description",
    ));
    row.append(&text);
    let shortcut = label(key, "key");
    shortcut.set_valign(gtk::Align::Center);
    row.append(&shortcut);
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

fn window() -> (gtk::Window, gtk::Box, glib::MainLoop) {
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
        .child(&body)
        .build();
    window.set_child(Some(&scroll));
    let loop_clone = main_loop.clone();
    window.connect_close_request(move |_| {
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
    (window, body, main_loop)
}

pub fn run(urls: &[String]) -> Result<()> {
    initialize()?;
    let (window, body, main_loop) = window();
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

    let routes = gtk::Box::new(gtk::Orientation::Vertical, 9);
    let status = label("1 / 2 / 3 / 4 / 5 to choose   ·   Esc to dismiss", "footer");
    status.set_margin_top(19);
    status.set_wrap(true);
    status.set_max_width_chars(48);
    let busy = Rc::new(Cell::new(false));
    let choices = [
        (
            Action::Chromium,
            "Chromium",
            "Open in Chromium",
            "chromium",
            "1",
            executable(&["chromium", "chromium-browser"]).is_some(),
        ),
        (
            Action::Firefox,
            "Firefox",
            "Open in Firefox",
            "firefox",
            "2",
            executable(&["firefox", "firefox-esr"]).is_some(),
        ),
        (
            Action::Copy,
            "Copy link",
            "Keep it on your clipboard",
            "edit-copy-symbolic",
            "3",
            true,
        ),
    ];
    let mut buttons = Vec::new();
    for (action, title, description, icon_name, key, available) in choices {
        let title = if action == Action::Copy && urls.len() > 1 {
            "Copy links"
        } else {
            title
        };
        let button = route_button(title, description, icon_name, key, available);
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
            let (sender, receiver) = std::sync::mpsc::channel();
            let urls = urls.clone();
            std::thread::spawn(move || {
                let _ = sender.send(execute(action, &urls));
            });
            let busy = busy.clone();
            let routes = routes.clone();
            let status = status.clone();
            let window = window.clone();
            glib::timeout_add_local(Duration::from_millis(25), move || {
                let result = match receiver.try_recv() {
                    Ok(result) => result,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        return glib::ControlFlow::Continue;
                    }
                    Err(_) => Err("The action did not complete. Please try again.".into()),
                };
                match result {
                    Ok(()) => {
                        status.add_css_class("success");
                        status.set_text(if action == Action::Copy {
                            "✓ Copied to clipboard"
                        } else {
                            "✓ Opening in your browser"
                        });
                        let window = window.clone();
                        glib::timeout_add_local_once(
                            Duration::from_millis(if action == Action::Copy { 750 } else { 200 }),
                            move || window.close(),
                        );
                    }
                    Err(error) => {
                        status.set_text(&error);
                        status.add_css_class("error");
                        routes.set_sensitive(true);
                        busy.set(false);
                    }
                }
                glib::ControlFlow::Break
            });
        });
        buttons.push(button);
    }
    let qr_button = route_button(
        "Show QR code",
        "Reveal for another device",
        "camera-photo-symbolic",
        "4",
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
        "5",
        true,
    );
    inspect_button.set_tooltip_text(Some(
        "Contacts the destination to check its connection; online reputation lookups are optional",
    ));
    let weak_window = window.downgrade();
    let inspect_link = urls[0].clone();
    inspect_button.connect_clicked(move |_| {
        if let Some(window) = weak_window.upgrade() {
            crate::inspector_ui::show(&window, &inspect_link, multiple);
        }
    });
    routes.append(&inspect_button);
    buttons.push(inspect_button);
    body.append(&routes);
    body.append(&status);
    let keys = gtk::EventControllerKey::new();
    keys.connect_key_pressed(move |_, key, _, modifiers| {
        if modifiers.intersects(
            gdk::ModifierType::CONTROL_MASK
                | gdk::ModifierType::ALT_MASK
                | gdk::ModifierType::SUPER_MASK,
        ) {
            return glib::Propagation::Proceed;
        }
        let index = match key {
            gdk::Key::_1 | gdk::Key::KP_1 => Some(0),
            gdk::Key::_2 | gdk::Key::KP_2 => Some(1),
            gdk::Key::_3 | gdk::Key::KP_3 => Some(2),
            gdk::Key::_4 | gdk::Key::KP_4 => Some(3),
            gdk::Key::_5 | gdk::Key::KP_5 => Some(4),
            _ => None,
        };
        if let Some(index) = index {
            if buttons[index].is_sensitive() {
                buttons[index].emit_clicked();
            }
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    window.add_controller(keys);
    window.present();
    main_loop.run();
    Ok(())
}

/// Desktop launchers have no URL; ask for one before displaying the chooser.
pub fn prompt() -> Result<Option<String>> {
    initialize()?;
    let (window, body, main_loop) = window();
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
    use super::destination;
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
