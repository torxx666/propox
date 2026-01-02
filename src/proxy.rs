use hyper::{Method, Request, Response, StatusCode};
use hyper::body::{Incoming, Bytes};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use crate::control; 
use log::error;
use http_body_util::{BodyExt, Full, Empty, combinators::BoxBody};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicU64, AtomicBool, Ordering};
use tokio::sync::mpsc::UnboundedSender;

// Generic error type
type BoxError = Box<dyn std::error::Error + Send + Sync>;

use std::collections::HashSet;
use std::sync::Mutex;
use std::net::IpAddr;
use std::time::Instant;
use dashmap::DashMap;

#[derive(Debug, Clone)]
pub enum LogLevel {
    Info,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub requests: AtomicUsize,
    pub bytes: AtomicU64,
    pub status_2xx: AtomicUsize,
    pub status_4xx: AtomicUsize,
    pub status_5xx: AtomicUsize,
    pub status_other: AtomicUsize,
    pub active_ips: DashMap<IpAddr, usize>,
    pub ip_errors: DashMap<IpAddr, usize>,
    // Rate Limiting: (Window Start Time, Request Count)
    pub ip_rate_limits: DashMap<IpAddr, (Instant, usize)>,
    pub blocked_set: Mutex<HashSet<IpAddr>>,
    pub blocked_history: Mutex<Vec<IpAddr>>,
    // We keep these for the TUI to read, but 'is_full_mode' is now managed by TUI state
    // Actually, TUI will update this AtomicBool so proxy knows whether to generate logs
    pub mode_full: AtomicBool,
    pub mode_error: AtomicBool,
    pub mode_benchmark: AtomicBool,
}

use std::net::SocketAddr;

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;

pub type HttpClient = Client<HttpConnector, Incoming>;

pub async fn handle_client(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    stats: Arc<Stats>,
    log_tx: UnboundedSender<LogEntry>,
    http_client: HttpClient,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, BoxError> {
    
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Check BENCHMARK MODE
    let is_benchmark = stats.mode_benchmark.load(Ordering::Relaxed);

    if !is_benchmark {
        // Track IP
        *stats.active_ips.entry(client_addr.ip()).or_default() += 1;
    }

    // Check BENCHMARK MODE (Bypass all security checks)
    if !is_benchmark {
        // RULE: GLOBAL BLOCK CHECK (Tarpit)
        // If IP is blocked (by Flood or Errors), delay and reject.
        {
            let is_blocked = if let Ok(set) = stats.blocked_set.lock() {
                set.contains(&client_addr.ip())
            } else { false };

            if is_blocked {
                 // TARPIT: Waste the attacker's time!
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(full("IP Blocked. Enjoy the wait."))
                    .unwrap());
            }
        }

        // RULE 1: RATE LIMITING (Flood Protection)
        // Threshold: 100 requests per second
        {
            let mut entry = stats.ip_rate_limits.entry(client_addr.ip()).or_insert((Instant::now(), 0));
            let (window_start, count) = entry.value_mut();
            
            if window_start.elapsed().as_secs() >= 1 {
                *window_start = Instant::now();
                *count = 1;
            } else {
                *count += 1;
                if *count > 100 {
                    // BLOCK!
                    let mut new_block = false;
                    if let Ok(mut set) = stats.blocked_set.lock() {
                        if set.insert(client_addr.ip()) {
                            new_block = true;
                            // Add to history
                            if let Ok(mut hist) = stats.blocked_history.lock() {
                                if hist.len() >= 3 { hist.remove(0); }
                                hist.push(client_addr.ip());
                            }
                        }
                    }
                    if new_block {
                         log_tx.send(LogEntry { level: LogLevel::Error, message: format!("FLOOD DETECTED: {}", client_addr.ip()) }).ok();
                    }
                    // We return 429 once, but next requests will hit the Global Block Check above
                    return Ok(Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS) 
                        .body(full("Rate Limit Exceeded. You are now blocked."))
                        .unwrap());
                }
            }
        }
    }

    if let Some(count) = stats.ip_errors.get(&client_addr.ip()) {
        if *count > 10 {
            // ... (Existing Error Block Logic) ...
            // Check if we already logged this block to avoid spam
            let mut new_block = false;
            if let Ok(mut set) = stats.blocked_set.lock() {
                if set.insert(client_addr.ip()) {
                    new_block = true;
                    // Add to history (keep last 3)
                    if let Ok(mut hist) = stats.blocked_history.lock() {
                        if hist.len() >= 3 { hist.remove(0); }
                        hist.push(client_addr.ip());
                    }
                }
            }

            if new_block {
                log_tx.send(LogEntry { level: LogLevel::Error, message: format!("BLOCKED IP: {}", client_addr.ip()) }).ok();
            }
            
            // Return 403 once, next requests hit the Global Tarpit
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full("IP Blocked due to excessive errors."))
                .unwrap());
        }
    }

    // Increment request count
    if !is_benchmark { stats.requests.fetch_add(1, Ordering::Relaxed); }

    // Helper to log
    let log_status = |status: StatusCode| {
        let is_full = stats.mode_full.load(Ordering::Relaxed);
        let is_err = stats.mode_error.load(Ordering::Relaxed);
        
        let is_error_status = status.is_client_error() || status.is_server_error();
        
        if is_full || (is_err && is_error_status) {
            let msg = format!("Request: {} {} {} -> {}", client_addr, method, uri, status);
            let level = if is_error_status { LogLevel::Error } else { LogLevel::Info };
            let _ = log_tx.send(LogEntry { level, message: msg });
        }
    };

    // Check with our control module (Flow Control)
    if let control::Action::Deny = control::check_flow(&req) {
         stats.status_4xx.fetch_add(1, Ordering::Relaxed);
         log_status(StatusCode::FORBIDDEN);
         return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(full("Blocked by proxy rules"))
            .unwrap());
    }

    if Method::CONNECT == req.method() {
        // HTTPS Tunneling
        if let Some(addr) = host_addr(req.uri()) {
            let tunnel_stats = stats.clone();
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr, tunnel_stats).await {
                            error!("tunnel error: {}", e);
                        };
                    }
                    Err(e) => error!("upgrade error: {}", e),
                }
            });
            stats.status_2xx.fetch_add(1, Ordering::Relaxed);
            log_status(StatusCode::OK);
            Ok(Response::new(empty()))
        } else {
             stats.status_4xx.fetch_add(1, Ordering::Relaxed);
             *stats.ip_errors.entry(client_addr.ip()).or_default() += 1;
             log_status(StatusCode::BAD_REQUEST);
             Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full("CONNECT must be to a socket address"))
                .unwrap())
        }
    } else {
        // Standard HTTP Proxy - USE IMPLICIT http_client passing? 
        // No, we use the passed http_client now.
        // let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        //    .build(hyper_util::client::legacy::connect::HttpConnector::new());

        match http_client.request(req).await {
             Ok(res) => {
                 let status = res.status();
                 log_status(status);

                 if !status.is_success() {
                     *stats.ip_errors.entry(client_addr.ip()).or_default() += 1;
                 }

                 match status.as_u16() {
                     200..=299 => { if !is_benchmark { stats.status_2xx.fetch_add(1, Ordering::Relaxed); }},
                     400..=499 => { if !is_benchmark { stats.status_4xx.fetch_add(1, Ordering::Relaxed); }},
                     500..=599 => { if !is_benchmark { stats.status_5xx.fetch_add(1, Ordering::Relaxed); }},
                     _ => { if !is_benchmark { stats.status_other.fetch_add(1, Ordering::Relaxed); }},
                 };

                 if let Some(len) = res.headers().get(hyper::header::CONTENT_LENGTH) {
                     if let Ok(s) = len.to_str() {
                         if let Ok(bytes) = s.parse::<u64>() {
                             if !is_benchmark { stats.bytes.fetch_add(bytes, Ordering::Relaxed); }
                         }
                     }
                 }
                 
                 let (parts, body) = res.into_parts();
                 let boxed_body = body.boxed(); 
                 Ok(Response::from_parts(parts, boxed_body))
             }
             Err(e) => {
                  let msg = format!("Proxy request error: {}", e);
                   let _ = log_tx.send(LogEntry { level: LogLevel::Error, message: msg.clone() });
                   
                   *stats.ip_errors.entry(client_addr.ip()).or_default() += 1;
                   stats.status_5xx.fetch_add(1, Ordering::Relaxed);
                  Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("Error: {}", e)))
                .unwrap())
             }
        }
    }
}

fn host_addr(uri: &hyper::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

async fn tunnel(upgraded: Upgraded, addr: String, stats: Arc<Stats>) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);
    
    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    stats.bytes.fetch_add(from_client + from_server, Ordering::Relaxed);
    Ok(())
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::new()
        .map_err(|never| match never {})
        .boxed()
}
