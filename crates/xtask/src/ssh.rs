use anyhow::{bail, Context as _, Result};
use shared::TargetHost;
use ssh2::Session as Ssh2Session;
use std::fs::File;
use std::io::Read;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct Session {
    sess: Ssh2Session,
}

impl Session {
    pub fn connect(t: &TargetHost) -> Result<Self> {
        let addr = format!("{}:{}", t.host, t.port);
        let tcp = TcpStream::connect_timeout(
            &addr
                .parse()
                .with_context(|| format!("parse {addr}"))?,
            Duration::from_secs(10),
        )
        .with_context(|| format!("tcp connect {addr}"))?;
        tcp.set_read_timeout(Some(Duration::from_secs(120)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(120)))?;
        let mut sess = Ssh2Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;
        let (user, key) = identity()?;
        sess.userauth_pubkey_file(&user, None, &key, None)
            .with_context(|| format!("ssh auth as {user} with {}", key.display()))?;
        if !sess.authenticated() {
            bail!("ssh authentication failed");
        }
        Ok(Self { sess })
    }

    pub fn run(&self, cmd: &str) -> Result<()> {
        let status = self.run_status(cmd)?;
        if status != 0 {
            bail!("remote command failed ({status}): {cmd}");
        }
        Ok(())
    }

    pub fn run_capture(&self, cmd: &str) -> Result<String> {
        let mut channel = self.sess.channel_session()?;
        channel.exec(cmd)?;
        let mut out = String::new();
        channel.read_to_string(&mut out)?;
        let mut err = String::new();
        channel.stderr().read_to_string(&mut err)?;
        channel.wait_close()?;
        let status = channel.exit_status()?;
        if status != 0 {
            bail!("remote failed ({status}): {cmd}\n{err}\n{out}");
        }
        Ok(out)
    }

    fn run_status(&self, cmd: &str) -> Result<i32> {
        let mut channel = self.sess.channel_session()?;
        channel.exec(cmd)?;
        let mut sink = Vec::new();
        channel.read_to_end(&mut sink)?;
        let mut err = Vec::new();
        channel.stderr().read_to_end(&mut err)?;
        channel.wait_close()?;
        let status = channel.exit_status()?;
        if status != 0 {
            eprintln!(
                "remote stderr: {}",
                String::from_utf8_lossy(&err)
            );
            eprintln!(
                "remote stdout: {}",
                String::from_utf8_lossy(&sink)
            );
        } else if !sink.is_empty() {
            print!("{}", String::from_utf8_lossy(&sink));
        }
        Ok(status)
    }

    pub fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        // Upload to a home-writable temp path first (avoids scp into root-owned dirs).
        let base = Path::new(remote)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("upload.bin");
        let tmp = format!("/tmp/drukarka-upload-{base}");
        let meta = std::fs::metadata(local)?;
        let mut file = File::open(local)?;
        let mut channel = self
            .sess
            .scp_send(Path::new(&tmp), 0o644, meta.len(), None)
            .with_context(|| format!("scp_send {tmp}"))?;
        std::io::copy(&mut file, &mut channel)?;
        channel.send_eof()?;
        channel.wait_eof()?;
        channel.close()?;
        channel.wait_close()?;
        if tmp != remote {
            self.run(&format!("sudo mv {tmp} {remote}"))?;
        }
        Ok(())
    }
}

fn identity() -> Result<(String, PathBuf)> {
    let home = std::env::var("HOME")?;
    let key = PathBuf::from(&home).join(".ssh/id_ed25519");
    if !key.exists() {
        bail!("missing {}", key.display());
    }
    Ok((shared::ADMIN_USER.to_string(), key))
}

pub fn wait_for_ssh(t: &TargetHost, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    let mut delay = Duration::from_secs(2);
    loop {
        if start.elapsed() > timeout {
            bail!("timed out waiting for SSH on {}", t.host);
        }
        match Session::connect(t) {
            Ok(_) => return Ok(()),
            Err(e) => {
                eprintln!("  waiting ({e:#})…");
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(15));
            }
        }
    }
}
