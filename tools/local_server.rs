use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const SECURITY_HEADERS: &str = concat!(
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Content-Security-Policy: default-src 'self'; ",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; ",
    "style-src 'self' 'unsafe-inline'; ",
    "connect-src 'self'; ",
    "img-src 'self' data:; ",
    "font-src 'self' data:; worker-src 'self' blob:; ",
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'\r\n"
);

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "py" => "text/x-python; charset=utf-8",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "png" => "image/png",
        "ico" => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn response(
    stream: &mut TcpStream,
    status: &str,
    body: &[u8],
    mime: &str,
    head_only: bool,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n{SECURITY_HEADERS}\r\n",
        body.len()
    )?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn serve(mut stream: TcpStream, web_root: &Path, backend_root: &Path) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 || request_line.len() > MAX_HEADER_BYTES {
        return response(&mut stream, "400 Bad Request", b"Bad Request", "text/plain", false);
    }
    let mut request = request_line.split_whitespace();
    let method = request.next().unwrap_or("");
    let target = request.next().unwrap_or("");
    if method != "GET" && method != "HEAD" {
        return response(&mut stream, "405 Method Not Allowed", b"Method Not Allowed", "text/plain", false);
    }
    let head_only = method == "HEAD";
    let mut header_bytes = request_line.len();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        header_bytes += read;
        if header_bytes > MAX_HEADER_BYTES {
            return response(&mut stream, "431 Request Header Fields Too Large", b"Headers Too Large", "text/plain", head_only);
        }
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }
    if target.is_empty() || target.contains('%') || target.contains('\\') {
        return response(&mut stream, "400 Bad Request", b"Bad Request", "text/plain", head_only);
    }

    let path = target.split('?').next().unwrap_or("/");
    let route = match path {
        "/" => "/index.html",
        "/docs" => "/docs.html",
        _ => path,
    };
    let (base, relative) = if let Some(value) = route.strip_prefix("/backend/") {
        (backend_root, value)
    } else {
        (web_root, route.trim_start_matches('/'))
    };
    let relative_path = Path::new(relative);
    if relative_path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return response(&mut stream, "400 Bad Request", b"Bad Request", "text/plain", head_only);
    }
    let candidate = base.join(relative_path);
    let resolved = match candidate.canonicalize() {
        Ok(value) if value.starts_with(base) && value.is_file() => value,
        _ => return response(&mut stream, "404 Not Found", b"Not Found", "text/plain", head_only),
    };
    let metadata = fs::metadata(&resolved)?;
    if metadata.len() > 60 * 1024 * 1024 {
        return response(&mut stream, "413 Content Too Large", b"Content Too Large", "text/plain", head_only);
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(&resolved)?.read_to_end(&mut body)?;
    response(&mut stream, "200 OK", &body, content_type(&resolved), head_only)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let root = PathBuf::from(args.next().ok_or("Usage: local-audit-server <project-root> <port>")?)
        .canonicalize()?;
    let port: u16 = args.next().ok_or("Missing port")?.parse()?;
    let web_root = root.join("web").canonicalize()?;
    let backend_root = root.join("backend").canonicalize()?;
    let address = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&address)?;
    println!("VBA Audit disponible sur http://{address}");

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(10)))?;
                stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                let web_root = web_root.clone();
                let backend_root = backend_root.clone();
                std::thread::spawn(move || {
                    if let Err(error) = serve(stream, &web_root, &backend_root) {
                        eprintln!("Erreur HTTP locale : {error}");
                    }
                });
            }
            Err(error) => eprintln!("Connexion locale impossible : {error}"),
        }
    }
    Ok(())
}
