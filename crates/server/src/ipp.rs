//! HTTP/IPP proxy on :631 for legacy Windows clients.
//! Rewrites `/ipp/print` → `/printers/HP_LaserJet_P1005` in the request line
//! and inside binary IPP attribute values.

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const OLD_PATH: &str = "/ipp/print";
const NEW_PATH: &str = "/printers/HP_LaserJet_P1005";

pub async fn run(listen: u16, cups_host: &str, cups_port: u16) -> Result<()> {
    // Dual-stack: Bonjour/Chrome often prefer the Avahi IPv6 AAAA; IPv4-only
    // listen made the discovered printer look "unavailable".
    let listener = bind_dual_stack(listen)
        .with_context(|| format!("bind dual-stack ipp :{listen}"))?;
    run_listener(listener, cups_host, cups_port).await
}

fn bind_dual_stack(port: u16) -> Result<TcpListener> {
    let addr = SocketAddr::from(([0u16; 8], port)); // [::]:port
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(false)?; // also accept IPv4-mapped on Linux
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

/// Accept loop on an already-bound listener (tests bind `127.0.0.1:0`).
pub async fn run_listener(
    listener: TcpListener,
    cups_host: &str,
    cups_port: u16,
) -> Result<()> {
    let addr = listener.local_addr()?;
    tracing::info!("IPP proxy on {addr} → {cups_host}:{cups_port}");
    let cups_host = cups_host.to_string();
    loop {
        let (client, peer) = listener.accept().await?;
        let host = cups_host.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(client, &host, cups_port).await {
                tracing::debug!("ipp {peer}: {e:#}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, cups_host: &str, cups_port: u16) -> Result<()> {
    let mut upstream = TcpStream::connect((cups_host, cups_port))
        .await
        .context("connect cups")?;

    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    let header_end = read_until_headers(&mut client, &mut buf, &mut tmp).await?;

    let (head, rest) = buf.split_at(header_end);
    let head_str = String::from_utf8_lossy(head);
    let mut lines: Vec<String> = head_str
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    if let Some(req) = lines.first_mut() {
        *req = req.replace(OLD_PATH, NEW_PATH);
    }

    // Public Host clients used (e.g. 192.168.18.30:631). CUPS answers with
    // job-uri ipp://127.0.0.1:8631/… which breaks Create-Job + Send-Document.
    let external_authority = lines
        .iter()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("host:")
                .map(|rest| rest.trim().to_string())
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| format!("{cups_host}:{cups_port}"));
    let cups_authority = format!("{cups_host}:{cups_port}");

    // CUPS defaults to Keep-Alive; without Connection: close the proxy would hang
    // forever waiting for EOF after a complete response.
    let mut saw_host = false;
    let mut saw_connection = false;
    let mut expect_continue = false;
    lines.retain(|line| {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("expect:") && lower.contains("100-continue") {
            expect_continue = true;
            return false; // strip — we handle Continue ourselves; CUPS gets the body directly
        }
        !lower.starts_with("proxy-connection:") && !lower.starts_with("keep-alive:")
    });
    for line in lines.iter_mut().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            *line = format!("Host: {cups_authority}");
            saw_host = true;
        } else if lower.starts_with("connection:") {
            *line = "Connection: close".into();
            saw_connection = true;
        }
    }
    if !saw_host {
        lines.push(format!("Host: {cups_host}:{cups_port}"));
    }
    if !saw_connection {
        lines.push("Connection: close".into());
    }

    // Clients (ipptool/CUPS) often send Expect: 100-continue and wait before the body.
    if expect_continue {
        client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
    }

    let content_length = content_length_of(&lines);
    let chunked_req = lines.iter().any(|l| {
        let lower = l.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });
    let mut body = rest.to_vec();
    if chunked_req {
        // Decode chunked body, then send upstream with Content-Length (cupsd is happier).
        body = read_chunked_body(&mut client, body, &mut tmp).await?;
        lines.retain(|l| !l.to_ascii_lowercase().starts_with("transfer-encoding:"));
        lines.push(format!("Content-Length: {}", body.len()));
    } else {
        while body.len() < content_length {
            let n = client.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        if content_length > 0 {
            body.truncate(content_length);
        }
    }

    // Only rewrite Win7 /ipp/print paths in small attribute-only payloads.
    // Send-Document / Print-Job carry a document after end-of-attributes — parsing
    // those as IPP attributes can truncate the body and hang the client.
    let ipp_op = if body.len() >= 4 {
        u16::from_be_bytes([body[2], body[3]])
    } else {
        0
    };
    const OP_PRINT_JOB: u16 = 0x0002;
    const OP_SEND_DOCUMENT: u16 = 0x0006;
    const OP_SEND_URI: u16 = 0x0007;
    let rewrite_req_path = !body.is_empty()
        && body.len() <= 16 * 1024
        && ipp_op != OP_SEND_DOCUMENT
        && ipp_op != OP_SEND_URI
        && !(ipp_op == OP_PRINT_JOB && body.len() > 4096)
        && find_subsequence(&body, OLD_PATH.as_bytes()).is_some();
    if rewrite_req_path {
        body = rewrite_ipp_body(&body, OLD_PATH.as_bytes(), NEW_PATH.as_bytes());
    }

    tracing::debug!(
        %external_authority,
        ipp_op,
        body_len = body.len(),
        chunked_req,
        rewrite_req_path,
        "ipp request"
    );

    for line in &mut lines {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            *line = format!("Content-Length: {}", body.len());
        }
    }

    // join alone cannot emit the header-terminating blank line; append it explicitly.
    let out = format!("{}\r\n\r\n", lines.join("\r\n"));
    upstream.write_all(out.as_bytes()).await?;
    if !body.is_empty() {
        upstream.write_all(&body).await?;
    }

    let resp = read_http_response(&mut upstream, &mut tmp).await?;
    let rewritten = rewrite_http_response(&resp, &cups_authority, &external_authority);
    client.write_all(&rewritten).await?;
    Ok(())
}

async fn read_until_headers(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<usize> {
    loop {
        let n = stream.read(tmp).await?;
        if n == 0 {
            anyhow::bail!("connection closed before headers");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(buf) {
            return Ok(pos);
        }
        if buf.len() > 1024 * 1024 {
            anyhow::bail!("headers too large");
        }
    }
}

/// Read one HTTP message. Prefer Content-Length; otherwise drain until EOF
/// (after we asked upstream for Connection: close).
async fn read_http_response(stream: &mut TcpStream, tmp: &mut [u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(8192);
    let header_end = read_until_headers(stream, &mut buf, tmp).await?;
    let head = &buf[..header_end];
    let head_str = String::from_utf8_lossy(head);
    let lines: Vec<&str> = head_str.split("\r\n").collect();
    let cl = content_length_of_str(&lines);
    let chunked = lines.iter().any(|l| {
        let lower = l.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    if let Some(len) = cl {
        while buf.len() < header_end + len {
            let n = stream.read(tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        buf.truncate(header_end + len);
        return Ok(buf);
    }

    if chunked {
        // Read until a terminating zero-chunk; then optional trailers + CRLF.
        loop {
            if let Some(end) = find_chunked_message_end(&buf[header_end..]) {
                buf.truncate(header_end + end);
                return Ok(buf);
            }
            let n = stream.read(tmp).await?;
            if n == 0 {
                return Ok(buf);
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 16 * 1024 * 1024 {
                anyhow::bail!("chunked response too large");
            }
        }
    }

    loop {
        let n = stream.read(tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 16 * 1024 * 1024 {
            anyhow::bail!("response too large");
        }
    }
    Ok(buf)
}

async fn read_chunked_body(
    stream: &mut TcpStream,
    mut buf: Vec<u8>,
    tmp: &mut [u8],
) -> Result<Vec<u8>> {
    loop {
        if let Some(end) = find_chunked_message_end(&buf) {
            let chunked = buf[..end].to_vec();
            return decode_chunked(&chunked);
        }
        let n = stream.read(tmp).await?;
        if n == 0 {
            anyhow::bail!("eof before chunked body finished");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 * 1024 {
            anyhow::bail!("chunked request too large");
        }
    }
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let mut out = Vec::new();
    while pos < body.len() {
        let rest = &body[pos..];
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("chunk size line")?;
        let size_line = std::str::from_utf8(&rest[..line_end]).context("chunk size utf8")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).context("chunk size hex")?;
        pos += line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size + 2 > body.len() {
            anyhow::bail!("truncated chunk");
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size + 2;
    }
    Ok(out)
}

/// Return byte length of a complete chunked body (including final 0 chunk + trailers),
/// measured from the start of the body.
fn find_chunked_message_end(body: &[u8]) -> Option<usize> {
    let mut pos = 0;
    while pos < body.len() {
        let rest = &body[pos..];
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        pos += line_end + 2;
        if size == 0 {
            // Empty trailers: `0\r\n\r\n`. Otherwise trailers then a blank line.
            if body[pos..].starts_with(b"\r\n") {
                return Some(pos + 2);
            }
            let trail = &body[pos..];
            let trail_end = trail.windows(4).position(|w| w == b"\r\n\r\n")?;
            return Some(pos + trail_end + 4);
        }
        if pos + size + 2 > body.len() {
            return None;
        }
        pos += size + 2; // data + CRLF
    }
    None
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn content_length_of(lines: &[String]) -> usize {
    content_length_of_str(&lines.iter().map(|s| s.as_str()).collect::<Vec<_>>()).unwrap_or(0)
}

fn content_length_of_str(lines: &[&str]) -> Option<usize> {
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn rewrite_http_response(
    resp: &[u8],
    cups_authority: &str,
    external_authority: &str,
) -> Vec<u8> {
    let Some(pos) = find_header_end(resp) else {
        return resp.to_vec();
    };
    let (head, body) = resp.split_at(pos);
    let head_str = String::from_utf8_lossy(head);
    let is_ipp = head_str.to_ascii_lowercase().contains("content-type: application/ipp");
    let chunked = head_str.to_ascii_lowercase().contains("transfer-encoding: chunked");
    // Only rewrite binary IPP; mangling HTML/chunked bodies breaks CUPS web/IPP clients.
    if !is_ipp || chunked {
        return resp.to_vec();
    }
    let mut new_body = rewrite_ipp_body(body, NEW_PATH.as_bytes(), OLD_PATH.as_bytes());
    // job-uri / printer-uri from cupsd point at the loopback listen address.
    if cups_authority != external_authority {
        new_body = rewrite_ipp_body(
            &new_body,
            cups_authority.as_bytes(),
            external_authority.as_bytes(),
        );
        // cupsd sometimes omits an explicit port or uses bare localhost.
        new_body = rewrite_ipp_body(&new_body, b"127.0.0.1:8631", external_authority.as_bytes());
        new_body = rewrite_ipp_body(&new_body, b"localhost:8631", external_authority.as_bytes());
    }
    if new_body.len() == body.len() && new_body == body {
        return resp.to_vec();
    }
    let mut lines: Vec<String> = head_str
        .split("\r\n")
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    for line in &mut lines {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            *line = format!("Content-Length: {}", new_body.len());
        }
    }
    let mut out = format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes();
    out.extend_from_slice(&new_body);
    out
}

/// Substitute `find` with `replace` inside IPP attribute values (length-prefixed).
pub fn rewrite_ipp_body(body: &[u8], find: &[u8], replace: &[u8]) -> Vec<u8> {
    if body.len() < 8 || find.is_empty() {
        return body.to_vec();
    }
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..8]);
    let mut pos = 8;
    let n = body.len();
    while pos < n {
        let tag = body[pos];
        out.push(tag);
        pos += 1;
        if tag == 0x03 {
            out.extend_from_slice(&body[pos..]);
            return out;
        }
        if tag >= 0x10 {
            if pos + 2 > n {
                break;
            }
            let name_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            out.extend_from_slice(&body[pos..pos + 2]);
            pos += 2;
            if pos + name_len > n {
                break;
            }
            out.extend_from_slice(&body[pos..pos + name_len]);
            pos += name_len;
            if pos + 2 > n {
                break;
            }
            let val_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;
            if pos + val_len > n {
                break;
            }
            let val = &body[pos..pos + val_len];
            pos += val_len;
            if let Some(idx) = find_subsequence(val, find) {
                let mut nv = Vec::with_capacity(val.len() - find.len() + replace.len());
                nv.extend_from_slice(&val[..idx]);
                nv.extend_from_slice(replace);
                nv.extend_from_slice(&val[idx + find.len()..]);
                out.extend_from_slice(&(nv.len() as u16).to_be_bytes());
                out.extend_from_slice(&nv);
            } else {
                out.extend_from_slice(&(val_len as u16).to_be_bytes());
                out.extend_from_slice(val);
            }
        }
    }
    out
}

fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Build a minimal IPP message with one uri attribute (for tests).
pub fn test_ipp_with_uri(uri: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x01, 0x01]); // version 1.1
    body.extend_from_slice(&0x0002u16.to_be_bytes()); // Print-Job
    body.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // request-id
    body.push(0x01); // operation-attributes-tag
    body.push(0x45); // uri tag
    let name = b"printer-uri";
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name);
    body.extend_from_slice(&(uri.len() as u16).to_be_bytes());
    body.extend_from_slice(uri.as_bytes());
    body.push(0x03); // end-of-attributes
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_printer_uri_path() {
        let body = test_ipp_with_uri("ipp://drukarka.local:631/ipp/print");
        let out = rewrite_ipp_body(&body, b"/ipp/print", b"/printers/HP_LaserJet_P1005");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("/printers/HP_LaserJet_P1005"));
        assert!(!s.contains("/ipp/print"));
    }

    #[test]
    fn rewrite_is_noop_when_absent() {
        let body = test_ipp_with_uri("ipp://drukarka.local:631/printers/X");
        let out = rewrite_ipp_body(&body, b"/ipp/print", b"/printers/HP_LaserJet_P1005");
        assert_eq!(out, body);
    }

    #[test]
    fn short_body_passthrough() {
        assert_eq!(rewrite_ipp_body(b"short", b"/a", b"/b"), b"short");
    }

    #[test]
    fn detects_chunked_terminator() {
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(find_chunked_message_end(body), Some(body.len()));
        assert_eq!(find_chunked_message_end(b"5\r\nhello\r\n0\r\n"), None);
    }

    #[test]
    fn rewrites_loopback_job_uri_authority() {
        let body = test_ipp_with_uri("ipp://127.0.0.1:8631/jobs/9");
        let out = rewrite_ipp_body(&body, b"127.0.0.1:8631", b"192.168.18.30:631");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("ipp://192.168.18.30:631/jobs/9"));
        assert!(!s.contains("127.0.0.1:8631"));
    }
}
