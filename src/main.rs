use std::{
    cell::RefCell,
    env,
    error::Error,
    fs::File,
    io::{BufRead, BufReader, prelude::*},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process,
    rc::Rc,
};

use httparse::{EMPTY_HEADER, Request};
use ssh2::{FileType, Session, Sftp};
use ssh2_config::{ParseRule, SshConfig};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = r#"Usage: remotely [OPTIONS] TARGET

A static file server that serves remote files over SSH.

Arguments:
  TARGET             Remote location in the form user@host:/path/to/dir

Options:
  -h, --host <HOST>  Local hostname or IP address (e.g. 127.0.0.1)
  -p, --port <PORT>  Local port number (default: 8000)
  --help             Show this help message
"#;

#[derive(Default)]
struct Config {
    local_host: String,
    local_port: String,
    remote_user: String,
    remote_host: String,
    remote_dir: String,
}

struct Connection {
    session: Session,
    sftp: Sftp,
}

type ConnectionRef = Rc<RefCell<Connection>>;

struct Server {
    conn: Option<ConnectionRef>,
}

enum State {
    Probe(ConnectionRef, Option<String>),
    Connected(ConnectionRef, Option<String>),
    Disconnected(Option<String>),
    Error(u16, String),
    Done,
}

fn make_html_response(code: u16, contents: &str) -> String {
    let contents = format!("{contents}\n");
    let status_line = format!("HTTP/1.1 {code} OK");
    let length = contents.len();
    format!(
        "{status_line}\r\n\
        Content-Type: text/html; charset=utf-8\r\n\
        Content-Length: {length}\r\n\r\n\
        {contents}"
    )
}

fn probe_state(
    server: &mut Server,
    conn: ConnectionRef,
    path: Option<String>,
) -> State {
    let ok = {
        let conn = conn.borrow();
        conn.session.channel_session().is_ok()
    };

    if ok {
        State::Connected(conn, path)
    } else {
        server.conn = None;
        State::Disconnected(path)
    }
}

fn disconnected_state(
    config: &Config,
    server: &mut Server,
    path: Option<String>,
) -> Result<State> {
    // Load the ssh config file
    let ssh_config = {
        let mut ssh_config_path = match env::var_os("HOME") {
            Some(home) => PathBuf::from(home),
            None => return Err("Failed to find home directory".into()),
        };
        ssh_config_path.extend(Path::new(".ssh/config"));
        let mut reader = BufReader::new(File::open(ssh_config_path)?);
        SshConfig::default().parse(&mut reader, ParseRule::STRICT)?
    };

    // Connect to the remote
    let tcp_stream = {
        let params = ssh_config.query(&config.remote_host);
        let host_name = match params.host_name {
            Some(host) => host,
            None => config.remote_host.clone(),
        };
        let port = match params.port {
            Some(port) => port.to_string(),
            None => "22".into(),
        };
        TcpStream::connect(format!("{host_name}:{port}"))?
    };

    // Configure the session
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp_stream);
    session.handshake()?;
    session.userauth_agent(&config.remote_user)?;

    if !session.authenticated() {
        return Ok(State::Error(200, "Failed to authenticate".into()));
    }

    let sftp = session.sftp()?;
    let conn = Rc::new(RefCell::new(Connection { session, sftp }));
    server.conn = Some(conn.clone());

    Ok(State::Connected(conn, path))
}

fn connected_state_dir(
    conn: ConnectionRef,
    filepath: &Path,
    stream: &mut TcpStream,
) -> Result<State> {
    let files = {
        let conn = conn.borrow();
        conn.sftp.readdir(filepath)?
    };

    let mut html = String::new();
    html.push_str(
        "\
        <!DOCTYPE HTML>\
        <html lang=\"en\">\
        <head>\
        <meta charset=\"utf-8\">\
        <title>Directory listing for /</title>\
        </head>\
        <body>
    ",
    );

    html.push_str(&format!(
        "<h1>Directory listing for {}</h1>\n<hr>\n<ul>\n",
        filepath.display(),
    ));

    for (file_path, file_stat) in files {
        let mut filename = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        match file_stat.file_type() {
            FileType::Directory => filename.push('/'),
            FileType::Symlink => filename.push('@'),
            _ => {}
        };
        html.push_str(&format!(
            r#"<li><a href="{filename}">{filename}</a></li>"#
        ));
    }

    html.push_str("</ul><hr></body>\n");

    let resp = make_html_response(200, &html);
    stream.write_all(resp.as_bytes())?;
    Ok(State::Done)
}

fn connected_state_file(
    conn: ConnectionRef,
    filepath: &Path,
    stream: &mut TcpStream,
    filesize: u64,
) -> Result<State> {
    let filename = filepath
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");

    let mime = mime_guess::from_path(filepath).first_or_octet_stream();

    let inline_types = [
        "text/",
        "image/",
        "application/json",
        "application/javascript",
        "application/xml",
    ];

    let mut headers = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: {filesize}\r\n\
         Content-Type: {mime}\r\n"
    );

    // Only force download if it’s not a typical inline type
    if !inline_types.iter().any(|p| mime.as_ref().starts_with(p)) {
        headers.push_str(&format!(
            "Content-Disposition: attachment; filename=\"{filename}\"\r\n"
        ));
    }

    headers.push_str("\r\n");

    stream.write_all(headers.as_bytes())?;

    // Send file contents
    let conn = conn.borrow();
    let mut buffer = [0u8; 8192];
    let mut file = conn.sftp.open(filepath)?;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        stream.write_all(&buffer[..n])?;
    }

    Ok(State::Done)
}

fn connected_state(
    config: &Config,
    conn: ConnectionRef,
    path: Option<String>,
    stream: &mut TcpStream,
) -> Result<State> {
    let mut filepath: PathBuf = Path::new(&config.remote_dir).into();
    if let Some(path) = path {
        filepath.extend(Path::new(&path[1..]));
    }
    let filepath = filepath.as_path();

    let stat = conn.borrow().sftp.stat(filepath)?;
    match stat.file_type() {
        FileType::Directory => connected_state_dir(conn, filepath, stream),
        FileType::RegularFile => {
            connected_state_file(conn, filepath, stream, stat.size.unwrap_or(0))
        }
        _ => Ok(State::Error(404, "Not found".into())),
    }
}

fn error_state(
    code: u16,
    reason: &str,
    stream: &mut TcpStream,
) -> Result<State> {
    let resp = make_html_response(code, reason);
    stream.write_all(resp.as_bytes())?;
    Ok(State::Done)
}

fn worker(
    config: &Config,
    server: &mut Server,
    mut stream: TcpStream,
) -> Result<()> {
    // Parse the http request
    let mut buf_reader = BufReader::new(&stream);
    let buf = buf_reader.fill_buf()?;
    let mut headers = [EMPTY_HEADER; 64];
    let mut request = Request::new(&mut headers);
    loop {
        let status = request.parse(buf)?;
        if status.is_complete() {
            break;
        }
    }

    println!(
        "{} {}",
        request.method.unwrap(),
        request.path.unwrap_or("/")
    );

    // Determine initial state
    let path = request.path.map(str::to_string);
    let mut state = match (request.method, server.conn.clone()) {
        (Some("GET"), Some(conn)) => State::Probe(conn, path),
        (Some("GET"), None) => State::Disconnected(path),
        (_, _) => State::Error(404, "Not found".into()),
    };

    loop {
        match state {
            State::Probe(conn, path) => {
                state = probe_state(server, conn, path);
            }
            State::Disconnected(path) => {
                state = match disconnected_state(config, server, path) {
                    Ok(state) => state,
                    Err(err) => State::Error(200, err.to_string()),
                };
            }
            State::Connected(conn, path) => {
                state = match connected_state(config, conn, path, &mut stream) {
                    Ok(state) => state,
                    Err(err) => State::Error(200, err.to_string()),
                };
            }
            State::Error(code, reason) => {
                state = error_state(code, &reason, &mut stream)?;
            }
            State::Done => {
                break;
            }
        }
    }

    Ok(())
}

fn config_from_args() -> Result<Config> {
    let mut args = env::args();

    args.next(); // skip program name

    let mut host = "127.0.0.1".into();
    let mut port = "8000".into();
    let mut target = String::new();
    let mut help = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => {
                help = true;
            }
            "-h" | "--host" => {
                if let Some(h) = args.next() {
                    host = h;
                }
            }
            "-p" | "--port" => {
                if let Some(p) = args.next() {
                    port = p.parse()?;
                }
            }
            _ => {
                if target.is_empty() {
                    target = arg;
                }
            }
        }
    }

    if help {
        print!("{USAGE}");
        process::exit(0);
    }

    if target.is_empty() {
        return Err("missing target".into());
    }

    let malformed_target_error = "malformed target";
    let (remote_user, rest) = match target.split_once('@') {
        Some(pair) => pair,
        None => return Err(malformed_target_error.into()),
    };

    let (remote_host, remote_dir) = match rest.split_once(':') {
        Some(pair) => pair,
        None => return Err(malformed_target_error.into()),
    };

    Ok(Config {
        local_host: host,
        local_port: port,
        remote_user: remote_user.into(),
        remote_host: remote_host.into(),
        remote_dir: remote_dir.into(),
    })
}

fn remotely_start() -> Result<()> {
    let config = config_from_args()?;
    let mut server = Server { conn: None };

    let local_addr = format!("{}:{}", config.local_host, config.local_port);
    let listener = TcpListener::bind(local_addr)?;

    println!(
        "Serving HTTP on {} port {}",
        config.local_host, config.local_port
    );

    for stream in listener.incoming() {
        worker(&config, &mut server, stream?)?;
    }

    Ok(())
}

fn main() {
    if let Err(err) = remotely_start() {
        eprintln!("{err}");
    }
}
