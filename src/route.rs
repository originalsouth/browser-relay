//! Transport-independent inspection state machine. Both UIs use the same consent rules.
use crate::{
    Result,
    link::{host, target},
};
use std::collections::HashSet;
use url::Url;
pub const MAX_HOPS: usize = 6;
#[derive(Debug, PartialEq)]
pub enum Next {
    Request,
    Consent(Url),
    Done,
}
#[derive(Debug, PartialEq)]
pub enum ResponseError {
    UnexpectedResponse,
    Redirect(String),
}
impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedResponse => f.write_str("Unexpected inspection response."),
            Self::Redirect(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for ResponseError {}

pub struct Route {
    url: Url,
    pending: Option<Url>,
    visited: HashSet<String>,
    pub names: Vec<String>,
    pub requests: usize,
    pub encrypted: bool,
    pub complete: bool,
    awaiting_response: bool,
}
pub fn next_redirect(current: &Url, location: &str) -> Result<Url> {
    let next = current
        .join(location)
        .map_err(|_| "Invalid redirect URL.")?;
    let next = target(next.as_str())?;
    if current.scheme() == "https" && next.scheme() == "http" {
        return Err("HTTPS redirects to unencrypted HTTP. The downgrade was not followed.".into());
    }
    Ok(next)
}
impl Route {
    pub fn new(link: &str) -> Result<Self> {
        Ok(Self {
            url: target(link)?,
            pending: None,
            visited: HashSet::new(),
            names: Vec::new(),
            requests: 0,
            encrypted: true,
            complete: false,
            awaiting_response: false,
        })
    }
    pub fn begin_request(&mut self) -> Result<Url> {
        if self.pending.is_some() || self.complete || self.awaiting_response {
            return Err("Inspection is not ready for another request.".into());
        }
        if self.requests >= MAX_HOPS {
            return Err(
                "Redirect limit reached: at most six requests across the entire inspection.".into(),
            );
        }
        if !self.visited.insert(self.url.to_string()) {
            return Err("Redirect loop detected.".into());
        }
        self.requests += 1;
        let name = host(&self.url);
        if self.names.last() != Some(&name) {
            self.names.push(name);
        }
        self.encrypted &= self.url.scheme() == "https";
        self.awaiting_response = true;
        Ok(self.url.clone())
    }
    pub fn response(
        &mut self,
        status: u16,
        location: Option<&str>,
    ) -> std::result::Result<Next, ResponseError> {
        if !self.awaiting_response || !(200..=999).contains(&status) {
            return Err(ResponseError::UnexpectedResponse);
        }
        self.awaiting_response = false;
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            self.complete = true;
            return Ok(Next::Done);
        }
        let next = next_redirect(
            &self.url,
            location.ok_or_else(|| {
                ResponseError::Redirect("Redirect has no readable Location header.".into())
            })?,
        )
        .map_err(ResponseError::Redirect)?;
        if self.requests == MAX_HOPS {
            return Err(ResponseError::Redirect(
                "Redirect limit reached: at most six requests across the entire inspection.".into(),
            ));
        }
        if next.origin() != self.url.origin() {
            self.pending = Some(next.clone());
            Ok(Next::Consent(next))
        } else {
            self.url = next;
            Ok(Next::Request)
        }
    }
    pub fn allow_redirect(&mut self) -> Result<()> {
        self.url = self
            .pending
            .take()
            .ok_or("No redirect is awaiting consent.")?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_exposure_is_recorded_before_any_response() {
        for status in [99, 101, 103, 200, 1000] {
            let mut route = Route::new("http://example.org").unwrap();
            route.begin_request().unwrap();
            assert!(!route.encrypted, "Even failed requests expose plain HTTP");
            let _ = route.response(status, None);
            assert!(!route.encrypted);
        }
    }
    #[test]
    fn informational_statuses_cannot_complete_an_inspection() {
        for status in 100..200 {
            let mut route = Route::new("https://example.org").unwrap();
            route.begin_request().unwrap();
            assert_eq!(
                route.response(status, None),
                Err(ResponseError::UnexpectedResponse)
            );
            assert!(!route.complete);
        }
        for status in [200, 299, 404, 599, 999] {
            let mut route = Route::new("https://example.org").unwrap();
            route.begin_request().unwrap();
            assert_eq!(route.response(status, None).unwrap(), Next::Done);
            assert!(route.complete);
        }
    }
    #[test]
    fn consent_preserves_history_and_earlier_http() {
        let mut r = Route::new("http://example.com/start#secret").unwrap();
        assert_eq!(r.begin_request().unwrap().fragment(), None);
        assert!(r.begin_request().is_err());
        assert!(matches!(
            r.response(302, Some("https://example.org/")).unwrap(),
            Next::Consent(_)
        ));
        assert!(r.begin_request().is_err());
        r.allow_redirect().unwrap();
        r.begin_request().unwrap();
        assert!(matches!(
            r.response(302, Some("https://example.com/end")).unwrap(),
            Next::Consent(_)
        ));
        r.allow_redirect().unwrap();
        r.begin_request().unwrap();
        assert_eq!(r.names, ["example.com", "example.org", "example.com"]);
        assert_eq!(r.response(200, None).unwrap(), Next::Done);
        assert!(!r.encrypted);
        assert!(r.complete);
        assert!(r.begin_request().is_err());
    }
    #[test]
    fn limits_loops_and_downgrades_are_shared() {
        let mut r = Route::new("https://example.com/").unwrap();
        r.begin_request().unwrap();
        assert!(matches!(
            r.response(302, Some("http://example.com/")),
            Err(ResponseError::Redirect(_))
        ));
        assert!(!r.complete);
        let mut r = Route::new("https://example.com/").unwrap();
        for i in 0..MAX_HOPS {
            r.begin_request().unwrap();
            let result = r.response(302, Some(&format!("/{i}")));
            assert_eq!(result.is_err(), i + 1 == MAX_HOPS);
        }
        assert!(r.begin_request().is_err());
        let mut r = Route::new("https://example.com/").unwrap();
        r.begin_request().unwrap();
        r.response(302, Some("/")).unwrap();
        assert!(r.begin_request().is_err());
    }
}
