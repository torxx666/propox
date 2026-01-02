use hyper::{Request, Response, StatusCode};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use http_body_util::{Full, combinators::BoxBody, BodyExt};
use std::net::SocketAddr;
use std::fs;
use std::io::Write;
use rand::Rng;
use std::path::Path;

// Generic error type
type BoxError = Box<dyn std::error::Error + Send + Sync>;

const FILES_DIR: &str = "test_files";

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn handle_request(req: Request<hyper::body::Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>, BoxError> {
    let path = req.uri().path();
    
    // Serve files from /test_files/
    if path.starts_with("/") {
        let filename = path.strip_prefix("/").unwrap_or("index.html");
        // Security check (very basic)
        if filename.contains("..") {
             return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full("Forbidden"))
                .unwrap());
        }

        let filepath = format!("{}/{}", FILES_DIR, filename);
        if Path::new(&filepath).exists() {
            match fs::read(&filepath) {
                Ok(content) => return Ok(Response::new(full(content))),
                Err(_) => return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(full("Error reading file"))
                    .unwrap()),
            }
        } else {
             return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full("Not Found"))
                .unwrap());
        }
    }
    
    Ok(Response::new(full("Hello! Request /file_N.txt to get a file.")))
}

fn generate_files() {
    if !Path::new(FILES_DIR).exists() {
        fs::create_dir(FILES_DIR).unwrap();
        println!("Created directory: {}", FILES_DIR);
    }
    
    let mut rng = rand::thread_rng();
    for i in 0..100 {
        let filename = format!("{}/file_{}.txt", FILES_DIR, i);
        if !Path::new(&filename).exists() {
             // Random size between 1KB and 100KB
             let size = rng.gen_range(1024..100 * 1024);
             let content: String = (0..size).map(|_| 'x').collect();
             let mut file = fs::File::create(&filename).unwrap();
             file.write_all(content.as_bytes()).unwrap();
        }
    }
    println!("Ensured 100 test files exist in {}", FILES_DIR);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    generate_files();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8200));
    let listener = TcpListener::bind(addr).await?;
    println!("Test Server listening on http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
