use hyper::Request;
// use log::info;

#[allow(dead_code)]
pub enum Action {
    Allow,
    Deny,
}

pub fn check_flow<B>(req: &Request<B>) -> Action {
    let uri = req.uri();
    let _host = uri.host().unwrap_or("unknown");
    // info!("Checking flow for host: {}", host);

    // Placeholder for more complex flow control (e.g. rate limiting, whitelisting)
    // currently allows everything, but proxy.rs handles IP blocking based on error rates.
    // if host.contains("example.org") { return Action::Deny; }

    Action::Allow
}
