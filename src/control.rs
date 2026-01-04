use hyper::Request;
// use log::info;

#[allow(dead_code)]
#[allow(dead_code)]
pub enum Action {
    Allow,
    Deny(String),
}

pub fn check_flow<B>(req: &Request<B>) -> Action {
    let uri = req.uri().to_string();
    let user_agent = req.headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // 1. WAF: Badge User-Agent Check
    // Block typical scanning tools and scripts
    let bad_agents = ["sqlmap", "nikto", "curl", "python", "hydra", "nmap"];
    if bad_agents.iter().any(|&agent| user_agent.contains(agent)) {
        return Action::Deny(format!("Bad User-Agent: {}", user_agent));
    }

    // 2. WAF: Sensitive Path Check
    // Block access to config files, git folders, and admin panels
    let bad_paths = [".env", ".git", "wp-config", "/admin", "phpinfo", ".htaccess"];
    if let Some(&path) = bad_paths.iter().find(|&&path| uri.contains(path)) {
        return Action::Deny(format!("Sensitive Path: {}", path));
    }

    // 3. WAF: SQL Injection / XSS Probe Check (Query String)
    // Decoded URI check would be better, but raw check catches most script kiddies
    let sqli_patterns = ["union select", "or 1=1", "drop table", "insert into", "<script>", "alert("];
    let uri_lower = uri.to_lowercase();
    if let Some(&pat) = sqli_patterns.iter().find(|&&pat| uri_lower.contains(pat)) {
         return Action::Deny(format!("Injection Attack: {}", pat));
    }

    Action::Allow
}
