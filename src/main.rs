use std::net::SocketAddr;
use std::sync::Arc;
use std::env;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::atomic::Ordering;
use std::io;
use std::time::Duration;
use syslog::{Facility, Formatter3164};

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::Style, // Removed Color/Modifier unused for now if not used, wait Color IS used below
    style::Color,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};

mod proxy;
mod control;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Channel for logs from proxy to TUI
    let (log_tx, mut log_rx) = mpsc::unbounded_channel();

    // Setup Stats
    let stats = Arc::new(proxy::Stats::default());
    
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "full") {
        stats.mode_full.store(true, Ordering::Relaxed);
    } else if args.iter().any(|arg| arg == "errors" || arg == "error") {
        stats.mode_error.store(true, Ordering::Relaxed);
    } else if args.iter().any(|arg| arg == "benchmark") {
         stats.mode_benchmark.store(true, Ordering::Relaxed);
    }
    
    // Start Proxy Server in Background
    let addr = SocketAddr::from(([127, 0, 0, 1], 8100));
    let listener = TcpListener::bind(addr).await?;
    
    // Create Global HTTP Client for Connection Pooling
    let http_client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());

    let server_stats = stats.clone();
    let server_log_tx = log_tx.clone();
    
    tokio::spawn(async move {
        loop {
            let (stream, client_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            
            let io = TokioIo::new(stream);
            let stats = server_stats.clone();
            let log_tx = server_log_tx.clone();
            let client = http_client.clone(); // Clone valid because Client is cheap to clone (internal Arc)

            tokio::task::spawn(async move {
                 if let Err(_err) = http1::Builder::new()
                    .serve_connection(io, service_fn(move |req| {
                        proxy::handle_client(req, client_addr, stats.clone(), log_tx.clone(), client.clone())
                    }))
                    .with_upgrades()
                    .await
                {
                    // Error logging
                }
            });
        }
    });

    // DAEMON MODE
    if args.iter().any(|arg| arg == "--daemon") {
        println!("Starting Propox in Daemon Mode (Logging to Syslog)...");
        
        let formatter = Formatter3164 {
            facility: Facility::LOG_USER,
            hostname: None,
            process: "propox".into(),
            pid: 0,
        };

        match syslog::unix(formatter) {
             Ok(mut logger) => {
                 while let Some(entry) = log_rx.recv().await {
                     match entry.level {
                         proxy::LogLevel::Info => { logger.info(entry.message).ok(); },
                         proxy::LogLevel::Error => { logger.err(entry.message).ok(); },
                     }
                 }
             }
             Err(e) => {
                 eprintln!("Failed to connect to syslog: {}", e);
                 // Fallback to stdout
                 while let Some(entry) = log_rx.recv().await {
                     println!("[{}] {}", if matches!(entry.level, proxy::LogLevel::Error) {"ERR"} else {"INFO"}, entry.message);
                 }
             }
        }
        return Ok(());
    }

    // Setup TUI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // TUI State
    let mut logs: Vec<proxy::LogEntry> = Vec::new();
    let max_logs = 500;

    let mut last_debug = "None".to_string();

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = std::time::Instant::now();
    let mut last_toggle = std::time::Instant::now(); // Re-add timer


    'mainloop: loop {
        // ... (Log collection omitted) ...
        
        // Collect new logs non-blocking
        while let Ok(entry) = log_rx.try_recv() {
            logs.push(entry);
            if logs.len() > max_logs {
                logs.remove(0);
            }
        }

        // Draw UI
        // ... (Drawing omitted) ...
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(7), // Header (Stats)
                        Constraint::Min(0),    // Logs
                    ]
                    .as_ref(),
                )
                .split(f.size());

            // 1. Stats Block
            let reqs = stats.requests.load(Ordering::Relaxed);
            let bytes = stats.bytes.load(Ordering::Relaxed);
            let s2 = stats.status_2xx.load(Ordering::Relaxed);
            let s4 = stats.status_4xx.load(Ordering::Relaxed);
            let s5 = stats.status_5xx.load(Ordering::Relaxed);
            
            // Generate IP Summary
            let mut ip_summary = "None".to_string();
            // DashMap iter() returns a RefMulti, need to collect carefully
            {
                 let mut sorted: Vec<(std::net::IpAddr, usize)> = stats.active_ips
                    .iter()
                    .map(|r| (*r.key(), *r.value()))
                    .collect();
                 sorted.sort_by(|a, b| b.1.cmp(&a.1));
                 
                 if !sorted.is_empty() {
                     ip_summary = sorted.iter().take(3)
                        .map(|(ip, c)| format!("{}:{}", ip, c))
                        .collect::<Vec<_>>().join(", ");
                 }
            }

            // Generate Blocked IP List
            let mut blocked_summary = "None".to_string();
            if let Ok(hist) = stats.blocked_history.lock() {
                if !hist.is_empty() {
                    blocked_summary = hist.iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>().join(", ");
                }
            }

            let mode_full = stats.mode_full.load(Ordering::Relaxed);
            let mode_err = stats.mode_error.load(Ordering::Relaxed);
            let mode_str = if mode_full { "FULL (All Logs)" } 
                          else if mode_err { "ERRORS (Only 4xx/5xx)" } 
                          else { "STATS (Logs Hidden)" };

            let stats_text = format!(
                "Requests: {}\nBytes: {}\nStatus: 2xx: {} | 4xx: {} | 5xx: {}\nActive IPs: [{}]\nBlocked IPs: [{}]\n\n>>> CURRENT MODE: {} <<<\nLast Input: {} (Press 'Space'/'f' to toggle Full, 'e' for Errors, 'a' to Quit)",
                reqs, bytes, s2, s4, s5, ip_summary, blocked_summary, mode_str, last_debug
            );

            let stats_paragraph = Paragraph::new(stats_text)
                .block(Block::default().title(" Proxy Stats ").borders(Borders::ALL));
            f.render_widget(stats_paragraph, chunks[0]);

            // 2. Logs Block
            let items: Vec<ListItem> = logs
                .iter()
                .rev() // Show newest first
                .map(|log| {
                    let style = match log.level {
                        proxy::LogLevel::Info => Style::default().fg(Color::White),
                        proxy::LogLevel::Error => Style::default().fg(Color::Red),
                    };
                    ListItem::new(log.message.clone()).style(style)
                })
                .collect();

            let logs_list = List::new(items)
                .block(Block::default().title(" Request Logs ").borders(Borders::ALL));
            f.render_widget(logs_list, chunks[1]);
        })?;

        // Handle Input
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
            
        if crossterm::event::poll(timeout)? {
            loop {
                if let Event::Key(key) = event::read()? {
                    // Show detailed debug info
                    last_debug = format!("{:?} {:?} {:?}", key.code, key.modifiers, key.kind); 
                    
                    match key.code {
                        KeyCode::Char(c) => match c.to_ascii_lowercase() {
                            'q' | 'a' => break 'mainloop, 
                            'f' | ' ' => {
                                if last_toggle.elapsed() > Duration::from_millis(300) {
                                    let current = stats.mode_full.load(Ordering::Relaxed);
                                    stats.mode_full.store(!current, Ordering::Relaxed);
                                    if !current { stats.mode_error.store(false, Ordering::Relaxed); }
                                    last_toggle = std::time::Instant::now();
                                }
                            },
                            'e' => {
                                if last_toggle.elapsed() > Duration::from_millis(300) {
                                    let current = stats.mode_error.load(Ordering::Relaxed);
                                    stats.mode_error.store(!current, Ordering::Relaxed);
                                    if !current { stats.mode_full.store(false, Ordering::Relaxed); }
                                    last_toggle = std::time::Instant::now();
                                }
                            },
                             _ => {}
                        },
                        _ => {}
                    }
                }
                
                if !crossterm::event::poll(Duration::from_secs(0))? {
                    break;
                }
            }
        }
        
        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }
    }

    // Restore Terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    Ok(())
}
