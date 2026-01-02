use std::time::Instant;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::net::IpAddr;
use std::io::{self, Write};
use std::env;
use rand::Rng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Default config
    let mut _base_ip_str = "127.0.0.1".to_string(); // Not used if pool is active
    let mut req_type = "ok".to_string(); // ok, nok, or mixed
    let mut count = 1000;
    let mut pool_size = 1;
    let mut error_ratio = 0.0; // 0.0 to 1.0 (e.g. 0.9 = 90% errors)

    // Parse args: ip=x rq=x nb=x cc=x pool=x ratio=x
    for arg in &args[1..] {
        if arg.starts_with("ip=") {
            _base_ip_str = arg.replace("ip=", "");
        } else if arg.starts_with("rq=") {
            req_type = arg.replace("rq=", "");
        } else if arg.starts_with("nb=") {
            if let Ok(n) = arg.replace("nb=", "").parse::<usize>() { count = n; }
        } else if arg.starts_with("cc=") {
            if let Ok(n) = arg.replace("cc=", "").parse::<usize>() {
                 env::set_var("CLIENT_CONCURRENCY", n.to_string());
            }
        } else if arg.starts_with("pool=") {
            if let Ok(n) = arg.replace("pool=", "").parse::<usize>() { pool_size = n; }
        } else if arg.starts_with("ratio=") {
            if let Ok(n) = arg.replace("ratio=", "").parse::<f64>() { error_ratio = n; }
        }
    }
    
    // Auto-set ratio if simple type provided (only for explicit NOK)
    if req_type == "nok" { error_ratio = 1.0; }
    // else if req_type == "ok" { error_ratio = 0.0; } // REMOVED: This was overwriting the ratio param!

    println!("Starting Load Test");
    println!("Config -> Type: {}, Count: {}, Pool: {} IPs, Error Ratio: {:.1}%", req_type, count, pool_size, error_ratio * 100.0);

    // Create Client Pool with distinct IPs
    let mut clients = Vec::new();
    let proxy = reqwest::Proxy::http("http://127.0.0.1:8100")?;

    // Parse starting octet from provided IP (e.g. 127.0.0.10 -> 10)
    let start_octet: usize = _base_ip_str.split('.')
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    
    for i in 0..pool_size {
        // Generate IPs starting from arg, ensuring valid range 2-254
        let raw_octet = start_octet + i;
        // Simple wrap around 2..254
        let octet = ((raw_octet - 2) % 253) + 2; 

        let ip_addr: IpAddr = format!("127.0.0.{}", octet).parse().unwrap();
        
        let client = Client::builder()
            .proxy(proxy.clone())
            .local_address(Some(ip_addr))
            .build()?;
        clients.push(client);
    }
    let clients = std::sync::Arc::new(clients);

    let base_url = "http://127.0.0.1:8200";
    let start_time = Instant::now();
    let success_count = AtomicUsize::new(0);
    let fail_count = AtomicUsize::new(0);

    let concurrency = env::var("CLIENT_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let bodies = stream::iter(0..count)
        .map(|i| {
            let clients_ref = clients.clone();
            // Pick rand client
            let client_idx = i % clients_ref.len();
            let client = &clients_ref[client_idx];
            let client = client.clone();
            
            // Determine type based on ratio
            let is_error_req = {
                let mut rng = rand::thread_rng();
                rng.gen_bool(error_ratio)
            };
            
            let url = if is_error_req {
                 format!("{}/file_{}.pdf", base_url, i % 100)
            } else {
                 format!("{}/file_{}.txt", base_url, i % 100)
            };

            async move {
                let resp = client.get(&url).send().await;
                (i, resp)
            }
        })
        .buffer_unordered(concurrency);

    bodies.for_each(|(i, result)| {
        let success = &success_count;
        let fail = &fail_count;
        async move {
            match result {
                Ok(resp) => {
                    if resp.status().is_success() {
                        success.fetch_add(1, Ordering::Relaxed);
                    } else {
                        fail.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Err(_) => {
                     fail.fetch_add(1, Ordering::Relaxed);
                }
            }
            
            // Progress Bar
            if i % 500 == 0 || i == count - 1 {
                let s = success.load(Ordering::Relaxed);
                let f = fail.load(Ordering::Relaxed);
                let pct = (i as f64 / count as f64) * 100.0;
                print!("\r\x1b[2KProgress: {:.1}% | \x1b[32mOK: {}\x1b[0m | \x1b[31mKO: {}\x1b[0m", pct, s, f);
                io::stdout().flush().unwrap();
            }
        }
    }).await;
    println!();

    // Print final "100%" line to be sure
    let s_count = success_count.load(Ordering::Relaxed);
    let f_count = fail_count.load(Ordering::Relaxed);
    print!("\r\x1b[2KProgress: 100.0% | \x1b[32mOK: {}\x1b[0m | \x1b[31mKO: {}\x1b[0m", s_count, f_count);
    println!();

    let total_time = start_time.elapsed();

    println!("---------------------------------------------------");
    println!("Completed in {:?}", total_time);
    println!("Success: {}", s_count);
    println!("Failed: {}", f_count);
    if count > 0 && total_time.as_secs_f64() > 0.0 {
         let rps = count as f64 / total_time.as_secs_f64();
         println!("Requests Per Second (RPS): {:.2}", rps);
         println!("Avg Time per Request: {:?}", total_time / count as u32);
    }
    println!("---------------------------------------------------");

    Ok(())
}
