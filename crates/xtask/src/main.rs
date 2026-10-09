mod ssh;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use shared::TargetHost;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "drukarka host workflows (via cargo aliases)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Link {
    Ethernet,
    Wifi,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Download Pi OS Lite, write SD, inject cloud-init + SSH key.
    Flash {
        #[arg(long, default_value = "/dev/sda")]
        disk: PathBuf,
        #[arg(long)]
        image: Option<PathBuf>,
        /// How the Pi should join the LAN on first boot.
        #[arg(long, value_enum, default_value_t = Link::Ethernet)]
        link: Link,
        /// Wi-Fi SSID (required with --link wifi). Or set DRUKARKA_WIFI_SSID.
        #[arg(long, env = "DRUKARKA_WIFI_SSID")]
        ssid: Option<String>,
        /// Wi-Fi password (required with --link wifi). Or set DRUKARKA_WIFI_PASSWORD.
        #[arg(long, env = "DRUKARKA_WIFI_PASSWORD")]
        password: Option<String>,
        /// Wi-Fi regulatory domain (default PL).
        #[arg(long, default_value = "PL", env = "DRUKARKA_WIFI_COUNTRY")]
        wifi_country: String,
    },
    /// Rewrite network-config on an already-mounted boot partition (no re-flash).
    Netconfig {
        /// Mounted bootfs path (e.g. /run/media/$USER/bootfs).
        #[arg(long)]
        boot: PathBuf,
        #[arg(long, value_enum)]
        link: Link,
        #[arg(long, env = "DRUKARKA_WIFI_SSID")]
        ssid: Option<String>,
        #[arg(long, env = "DRUKARKA_WIFI_PASSWORD")]
        password: Option<String>,
        #[arg(long, default_value = "PL", env = "DRUKARKA_WIFI_COUNTRY")]
        wifi_country: String,
    },
    /// First-boot packages, CA, CUPS, units (over SSH).
    Bootstrap {
        #[arg(long)]
        host: Option<String>,
    },
    /// Cross-compile server for aarch64.
    BuildPi,
    /// Build, upload release, flip current, restart, health-check.
    Deploy {
        #[arg(long)]
        host: Option<String>,
    },
    /// Flip current ↔ previous and restart.
    Rollback {
        #[arg(long)]
        host: Option<String>,
    },
    /// Apply pending DB migrations on the Pi.
    Migrate {
        #[arg(long)]
        host: Option<String>,
    },
    /// Print a one-time passkey enroll URL.
    Enroll {
        #[arg(long)]
        host: Option<String>,
    },
    /// Remote health summary.
    Status {
        #[arg(long)]
        host: Option<String>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Flash {
            disk,
            image,
            link,
            ssid,
            password,
            wifi_country,
        } => {
            let net = resolve_net(link, ssid, password, wifi_country)?;
            flash(&disk, image.as_deref(), &net)
        }
        Cmd::Netconfig {
            boot,
            link,
            ssid,
            password,
            wifi_country,
        } => {
            let net = resolve_net(link, ssid, password, wifi_country)?;
            write_network_config(&boot, &net)?;
            println!("==> wrote network-config ({link:?}) to {}", boot.display());
            Ok(())
        }
        Cmd::Bootstrap { host } => bootstrap(target(host)),
        Cmd::BuildPi => build_pi().map(|_| ()),
        Cmd::Deploy { host } => deploy(target(host)),
        Cmd::Rollback { host } => rollback(target(host)),
        Cmd::Migrate { host } => migrate(target(host)),
        Cmd::Enroll { host } => enroll(target(host)),
        Cmd::Status { host } => status(target(host)),
    }
}

struct NetConfig {
    link: Link,
    ssid: Option<String>,
    password: Option<String>,
    country: String,
}

fn resolve_net(
    link: Link,
    ssid: Option<String>,
    password: Option<String>,
    country: String,
) -> Result<NetConfig> {
    match link {
        Link::Ethernet => Ok(NetConfig {
            link,
            ssid: None,
            password: None,
            country,
        }),
        Link::Wifi => {
            let ssid = ssid.filter(|s| !s.is_empty()).context(
                "--link wifi requires --ssid (or DRUKARKA_WIFI_SSID)",
            )?;
            let password = password.filter(|s| !s.is_empty()).context(
                "--link wifi requires --password (or DRUKARKA_WIFI_PASSWORD)",
            )?;
            Ok(NetConfig {
                link,
                ssid: Some(ssid),
                password: Some(password),
                country,
            })
        }
    }
}

fn yaml_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn network_config_yaml(net: &NetConfig) -> String {
    match net.link {
        Link::Ethernet => r#"network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: true
      optional: true
"#
        .to_string(),
        Link::Wifi => {
            let ssid = yaml_quote(net.ssid.as_deref().unwrap());
            let password = yaml_quote(net.password.as_deref().unwrap());
            let country = yaml_quote(&net.country);
            format!(
                r#"network:
  version: 2
  wifis:
    wlan0:
      dhcp4: true
      dhcp6: true
      regulatory-domain: {country}
      access-points:
        {ssid}:
          password: {password}
      optional: true
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: true
      optional: true
"#
            )
        }
    }
}

fn write_network_config(boot: &Path, net: &NetConfig) -> Result<()> {
    if !boot.exists() {
        bail!("boot path does not exist: {}", boot.display());
    }
    let path = boot.join("network-config");
    fs::write(&path, network_config_yaml(net))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn target(host: Option<String>) -> TargetHost {
    let mut t = TargetHost::default();
    if let Some(h) = host {
        t.host = h;
    }
    t
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cache_dir() -> Result<PathBuf> {
    let p = repo_root().join("out").join("cache");
    fs::create_dir_all(&p)?;
    Ok(p)
}

// --- flash ---

const IMAGE_URL: &str = "https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2026-10-06/2026-10-06-raspios-trixie-arm64-lite.img.xz";

fn flash(disk: &Path, image: Option<&Path>, net: &NetConfig) -> Result<()> {
    verify_disk(disk)?;
    let img_xz = if let Some(p) = image {
        p.to_path_buf()
    } else {
        download_image()?
    };
    println!("==> decompressing {}", img_xz.display());
    let img = decompress_xz(&img_xz)?;
    println!("==> unmounting partitions on {}", disk.display());
    unmount_disk(disk)?;
    println!("==> writing {} → {} (this takes a few minutes)", img.display(), disk.display());
    write_image(&img, disk)?;
    println!("==> waiting for partitions…");
    std::thread::sleep(Duration::from_secs(2));
    // partprobe
    let _ = Command::new("partprobe").arg(disk).status();
    std::thread::sleep(Duration::from_secs(2));
    let boot = find_boot_partition(disk)?;
    let mnt = repo_root().join("out").join("mnt-boot");
    let _ = fs::remove_dir_all(&mnt);
    fs::create_dir_all(&mnt)?;
    mount_vfat(&boot, &mnt)?;
    inject_cloud_init(&mnt, net)?;
    umount(&mnt)?;
    println!(
        "==> flash complete ({:?}). Eject SD, insert in Pi, power on, then say ready.",
        net.link
    );
    Ok(())
}

fn verify_disk(disk: &Path) -> Result<()> {
    let canon = disk.canonicalize().unwrap_or_else(|_| disk.to_path_buf());
    if !canon.starts_with("/dev/") {
        bail!("refusing non-device path {}", disk.display());
    }
    // Safety: only the 14.4G reader we've seen (or force via size check).
    let sysfs = PathBuf::from(format!(
        "/sys/block/{}/size",
        canon.file_name().unwrap().to_string_lossy()
    ));
    let sectors: u64 = fs::read_to_string(&sysfs)
        .with_context(|| format!("read {}", sysfs.display()))?
        .trim()
        .parse()?;
    let bytes = sectors * 512;
    // Expect ~14–16 GiB removable media; refuse NVMe/large disks.
    if bytes < 8_000_000_000 || bytes > 20_000_000_000 {
        bail!(
            "disk {} is {} bytes — refusing (expected ~14GB SD reader). Pass the correct --disk.",
            disk.display(),
            bytes
        );
    }
    Ok(())
}

fn download_image() -> Result<PathBuf> {
    let cache = cache_dir()?;
    let name = IMAGE_URL.rsplit('/').next().unwrap();
    let dest = cache.join(name);
    if dest.exists() && dest.metadata()?.len() > 100_000_000 {
        println!("==> using cached {}", dest.display());
        return Ok(dest);
    }
    println!("==> downloading {IMAGE_URL}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()?;
    let mut resp = client.get(IMAGE_URL).send()?.error_for_status()?;
    let mut tmp = File::create(&dest)?;
    let mut written = 0u64;
    let mut buf = [0u8; 1024 * 256];
    loop {
        let n = resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        tmp.write_all(&buf[..n])?;
        written += n as u64;
        if written % (50 * 1024 * 1024) < n as u64 {
            println!("    … {:.0} MiB", written as f64 / 1_048_576.0);
        }
    }
    Ok(dest)
}

fn decompress_xz(xz: &Path) -> Result<PathBuf> {
    let out = xz.with_extension("").with_extension("img");
    // path like foo.img.xz → foo.img
    let out = if xz.extension().and_then(|e| e.to_str()) == Some("xz") {
        PathBuf::from(xz.to_string_lossy().trim_end_matches(".xz"))
    } else {
        out
    };
    if out.exists() && out.metadata()?.len() > 1_000_000_000 {
        println!("==> using existing {}", out.display());
        return Ok(out);
    }
    let mut decoder = xz2::read::XzDecoder::new(File::open(xz)?);
    let mut dest = File::create(&out)?;
    std::io::copy(&mut decoder, &mut dest)?;
    Ok(out)
}

fn unmount_disk(disk: &Path) -> Result<()> {
    let name = disk.file_name().unwrap().to_string_lossy();
    for ent in fs::read_dir("/dev")? {
        let p = ent?.path();
        let n = p.file_name().unwrap().to_string_lossy();
        if n.starts_with(&*name) && n != name {
            let _ = Command::new("umount").arg(&p).status();
        }
    }
    // also common mountpoints
    let _ = Command::new("umount").arg("/run/media/jan/bootfs").status();
    let _ = Command::new("umount").arg("/run/media/jan/rootfs").status();
    Ok(())
}

fn write_image(img: &Path, disk: &Path) -> Result<()> {
    // Prefer dd with oflag=dsync for progress-ish; pure Rust write also works but slower flush.
    // Project rule: host workflows in Rust — we open the block device from Rust.
    let mut src = File::open(img)?;
    let mut dst = fs::OpenOptions::new().write(true).open(disk)
        .with_context(|| format!("open {} for write (need root)", disk.display()))?;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut written = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        written += n as u64;
        if written % (256 * 1024 * 1024) < n as u64 {
            println!("    wrote {:.1} GiB", written as f64 / 1_073_741_824.0);
        }
    }
    dst.sync_all()?;
    Ok(())
}

fn find_boot_partition(disk: &Path) -> Result<PathBuf> {
    // /dev/sda1 or /dev/mmcblk0p1
    let candidates = [
        PathBuf::from(format!("{}1", disk.display())),
        PathBuf::from(format!("{}p1", disk.display())),
    ];
    for c in candidates {
        if c.exists() {
            return Ok(c);
        }
    }
    bail!("boot partition not found for {}", disk.display());
}

fn mount_vfat(dev: &Path, mnt: &Path) -> Result<()> {
    let st = Command::new("mount")
        .args(["-t", "vfat", &dev.to_string_lossy(), &mnt.to_string_lossy()])
        .status()?;
    if !st.success() {
        bail!("mount failed");
    }
    Ok(())
}

fn umount(mnt: &Path) -> Result<()> {
    let st = Command::new("umount").arg(mnt).status()?;
    if !st.success() {
        bail!("umount failed");
    }
    Ok(())
}

fn inject_cloud_init(boot: &Path, net: &NetConfig) -> Result<()> {
    let pubkey = fs::read_to_string(dirs_ssh_pubkey()?).context("read ssh pubkey")?;
    let pubkey = pubkey.trim();
    // Enable SSH (classic marker + cloud-init)
    File::create(boot.join("ssh"))?;
    let user_data = format!(
        r#"#cloud-config
hostname: {host}
manage_etc_hosts: true
timezone: Europe/Warsaw
keyboard:
  model: pc105
  layout: "pl"
users:
  - name: {user}
    groups: sudo, adm
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - "{pubkey}"
ssh_pwauth: false
package_update: false
runcmd:
  - [ systemctl, enable, --now, ssh ]
"#,
        host = shared::HOSTNAME,
        user = shared::ADMIN_USER,
        pubkey = pubkey
    );
    fs::write(boot.join("user-data"), user_data)?;
    fs::write(
        boot.join("meta-data"),
        "instance-id: drukarka-0\nlocal-hostname: drukarka\n",
    )?;
    write_network_config(boot, net)?;
    match net.link {
        Link::Ethernet => println!("==> cloud-init + SSH key (ethernet DHCP)"),
        Link::Wifi => println!(
            "==> cloud-init + SSH key (wifi SSID {})",
            net.ssid.as_deref().unwrap_or("?")
        ),
    }
    Ok(())
}

fn dirs_ssh_pubkey() -> Result<PathBuf> {
    let home = std::env::var("HOME")?;
    let p = PathBuf::from(home).join(".ssh/id_ed25519.pub");
    if !p.exists() {
        bail!("missing {}", p.display());
    }
    Ok(p)
}

// --- build / deploy ---

fn build_pi() -> Result<PathBuf> {
    let root = repo_root();
    println!("==> cross-compiling server for aarch64");
    let st = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "server",
            "--release",
            "--target",
            "aarch64-unknown-linux-gnu",
        ])
        .status()?;
    if !st.success() {
        bail!("cross-compile failed — is aarch64-linux-gnu-gcc installed?");
    }
    let bin = root
        .join("target/aarch64-unknown-linux-gnu/release/drukarka-server");
    if !bin.exists() {
        bail!("missing {}", bin.display());
    }
    Ok(bin)
}

fn deploy(t: TargetHost) -> Result<()> {
    let bin = build_pi()?;
    let id = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let remote_dir = format!("{}/{}", shared::RELEASES_DIR, id);
    println!("==> deploying release {id} to {}", t.host);
    let s = ssh::Session::connect(&t)?;
    s.run(&format!(
        "sudo mkdir -p {} {} /var/lib/drukarka && sudo chown {} /var/lib/drukarka",
        shared::RELEASES_DIR,
        remote_dir,
        shared::ADMIN_USER
    ))?;
    s.upload(&bin, &format!("{remote_dir}/drukarka-server"))?;
    s.run(&format!("chmod +x {remote_dir}/drukarka-server"))?;
    // migrate before flip
    s.run(&format!(
        "sudo {remote_dir}/drukarka-server migrate || true"
    ))?;
    s.run(&format!(
        "if [ -L {cur} ]; then sudo ln -sfn $(readlink -f {cur}) {prev}; fi; sudo ln -sfn {remote_dir} {cur}",
        cur = shared::CURRENT_LINK,
        prev = shared::PREVIOUS_LINK,
        remote_dir = remote_dir
    ))?;
    install_units(&s)?;
    s.run("sudo systemctl daemon-reload")?;
    s.run("sudo systemctl enable --now drukarka-server drukarka-ipp")?;
    s.run("sudo systemctl restart drukarka-server drukarka-ipp")?;
    std::thread::sleep(Duration::from_secs(2));
    let health = s.run_capture(
        "curl -sk https://127.0.0.1/healthz || curl -sk https://drukarka.local/healthz || echo FAIL",
    )?;
    println!("health: {}", health.trim());
    if !health.contains("ok") {
        bail!("health check failed after deploy");
    }
    println!("==> deploy {id} ok");
    Ok(())
}

fn install_units(s: &ssh::Session) -> Result<()> {
    let root = repo_root();
    for name in ["drukarka-server.service", "drukarka-ipp.service"] {
        let local = root.join("deploy").join(name);
        let remote = format!("/tmp/{name}");
        s.upload(&local, &remote)?;
        s.run(&format!("sudo mv {remote} /etc/systemd/system/{name}"))?;
    }
    Ok(())
}

fn rollback(t: TargetHost) -> Result<()> {
    let s = ssh::Session::connect(&t)?;
    s.run(&format!(
        "test -L {prev} || {{ echo 'no previous release'; exit 1; }}; \
         CUR=$(readlink -f {cur}); PREV=$(readlink -f {prev}); \
         sudo ln -sfn \"$CUR\" {prev}.swap; sudo ln -sfn \"$PREV\" {cur}; sudo ln -sfn \"$CUR\" {prev}; \
         sudo systemctl restart drukarka-server drukarka-ipp",
        cur = shared::CURRENT_LINK,
        prev = shared::PREVIOUS_LINK
    ))?;
    println!("==> rolled back");
    status(t)
}

fn migrate(t: TargetHost) -> Result<()> {
    let s = ssh::Session::connect(&t)?;
    let out = s.run_capture(&format!(
        "sudo {}/drukarka-server migrate",
        shared::CURRENT_LINK
    ))?;
    println!("{out}");
    Ok(())
}

fn enroll(t: TargetHost) -> Result<()> {
    let s = ssh::Session::connect(&t)?;
    let out = s.run_capture(&format!(
        "sudo {}/drukarka-server generate-enroll-link",
        shared::CURRENT_LINK
    ))?;
    println!("{}", out.trim());
    Ok(())
}

fn status(t: TargetHost) -> Result<()> {
    let s = ssh::Session::connect(&t)?;
    let out = s.run_capture(&format!(
        "echo HOST:$(hostname); echo CURRENT:$(readlink -f {cur} 2>/dev/null); \
         systemctl is-active drukarka-server drukarka-ipp cups 2>/dev/null; \
         curl -sk -o /dev/null -w 'health:%{{http_code}}\\n' https://127.0.0.1/healthz; \
         lpstat -p 2>/dev/null | head -5",
        cur = shared::CURRENT_LINK
    ))?;
    println!("{out}");
    Ok(())
}

fn bootstrap(t: TargetHost) -> Result<()> {
    println!("==> waiting for SSH on {}…", t.host);
    ssh::wait_for_ssh(&t, Duration::from_secs(300))?;
    let s = ssh::Session::connect(&t)?;
    println!("==> installing packages (small batches — apt thrashing on Pi)");
    s.run("sudo DEBIAN_FRONTEND=noninteractive apt-get update -y")?;
    // Install in batches so apt does not OOM a 4GB Pi.
    for batch in [
        "ca-certificates curl openssl",
        "avahi-daemon avahi-utils",
        "cups cups-bsd cups-client",
        "cups-filters cups-browsed",
        "hplip printer-driver-hpcups",
    ] {
        println!("    apt: {batch}");
        s.run(&format!(
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {batch}"
        ))?;
    }
    // HPLIP plugin — best effort (P1005)
    let _ = s.run(
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends hplip-data || true",
    );
    println!("==> local CA");
    ensure_ca(&s, &t.host)?;
    println!("==> CUPS config");
    let cups_conf = repo_root().join("deploy/cupsd-drukarka.conf");
    s.upload(&cups_conf, "/tmp/cupsd-drukarka.conf")?;
    s.run(
        "sudo cp /tmp/cupsd-drukarka.conf /etc/cups/cupsd.conf && \
         sudo systemctl enable --now cups avahi-daemon && \
         sudo systemctl restart cups",
    )?;
    // Add printer if USB present
    let _ = s.run(&format!(
        "sudo lpadmin -p {name} -E -v 'hp:/usb/HP_LaserJet_P1005?serial=*' \
           -m drv:///hpcups.drv/hp-laserjet_p1005.ppd 2>/dev/null || \
         sudo lpadmin -p {name} -E -v usb://HP/LaserJet%20P1005 -m everywhere 2>/dev/null || true; \
         sudo cupsenable {name} 2>/dev/null; sudo cupsaccept {name} 2>/dev/null; \
         sudo lpadmin -p {name} -o printer-is-shared=true 2>/dev/null || true",
        name = shared::PRINTER_NAME
    ));
    s.run(&format!(
        "sudo mkdir -p {} /var/lib/drukarka && sudo chown {} /var/lib/drukarka",
        shared::OPT_ROOT,
        shared::ADMIN_USER
    ))?;
    // Bonjour/AirPrint: CUPS is localhost-only, so advertise IPP via Avahi → :631 proxy.
    let avahi = repo_root().join("deploy/avahi-printer.service");
    if avahi.exists() {
        s.upload(&avahi, "/tmp/avahi-printer.service")?;
        s.run(
            "sudo mv /tmp/avahi-printer.service /etc/avahi/services/printer.service && \
             sudo systemctl restart avahi-daemon",
        )?;
        println!("==> Avahi IPP/AirPrint service installed");
    }
    println!("==> bootstrap base done — run cargo deploy next");
    Ok(())
}

fn ensure_ca(s: &ssh::Session, host: &str) -> Result<()> {
    // Generate on host with rcgen, upload — keeps CA copy in out/ca.crt
    let out = repo_root().join("out");
    fs::create_dir_all(&out)?;
    let ca_key_path = out.join("ca.key");
    let ca_cert_path = out.join("ca.crt");
    let leaf_key = out.join("drukarka.key");
    let leaf_cert = out.join("drukarka.crt");

    let ca_key = if ca_key_path.exists() {
        rcgen::KeyPair::from_pem(&fs::read_to_string(&ca_key_path)?)?
    } else {
        let kp = rcgen::KeyPair::generate()?;
        fs::write(&ca_key_path, kp.serialize_pem())?;
        kp
    };

    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "drukarka local CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    fs::write(&ca_cert_path, ca_cert.pem())?;

    // SAN: DNS name + any concrete IPs we know (current host, optional reservation).
    let mut sans = vec![shared::DOMAIN.to_string()];
    if host.parse::<std::net::IpAddr>().is_ok() {
        sans.push(host.to_string());
    }
    if shared::STATIC_IP != host {
        sans.push(shared::STATIC_IP.to_string());
    }
    sans.sort();
    sans.dedup();

    let mut leaf = rcgen::CertificateParams::new(sans)?;
    leaf.distinguished_name
        .push(rcgen::DnType::CommonName, shared::DOMAIN);
    let leaf_kp = rcgen::KeyPair::generate()?;
    let leaf_signed = leaf.signed_by(&leaf_kp, &ca_cert, &ca_key)?;
    fs::write(&leaf_cert, leaf_signed.pem())?;
    fs::write(&leaf_key, leaf_kp.serialize_pem())?;

    s.run(&format!("sudo mkdir -p {}", shared::CA_DIR))?;
    s.upload(&leaf_cert, "/tmp/drukarka.crt")?;
    s.upload(&leaf_key, "/tmp/drukarka.key")?;
    s.upload(&ca_cert_path, "/tmp/ca.crt")?;
    s.run(&format!(
        "sudo mv /tmp/drukarka.crt /tmp/drukarka.key /tmp/ca.crt {}/ && \
         sudo chmod 640 {}/drukarka.key && sudo chmod 644 {}/drukarka.crt {}/ca.crt",
        shared::CA_DIR,
        shared::CA_DIR,
        shared::CA_DIR,
        shared::CA_DIR
    ))?;
    s.run(&format!(
        "sudo cp {}/ca.crt /usr/local/share/ca-certificates/drukarka.crt && sudo update-ca-certificates || true",
        shared::CA_DIR
    ))?;
    println!("==> CA written to {}", ca_cert_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_yaml_has_no_wifi() {
        let net = resolve_net(Link::Ethernet, None, None, "PL".into()).unwrap();
        let y = network_config_yaml(&net);
        assert!(y.contains("eth0"));
        assert!(!y.contains("wlan0"));
        assert!(!y.contains("access-points"));
    }

    #[test]
    fn wifi_yaml_includes_ssid_not_hardcoded_secrets() {
        let net = resolve_net(
            Link::Wifi,
            Some("MyNet".into()),
            Some("s3cret".into()),
            "PL".into(),
        )
        .unwrap();
        let y = network_config_yaml(&net);
        assert!(y.contains("wlan0"));
        assert!(y.contains("\"MyNet\""));
        assert!(y.contains("\"s3cret\""));
        assert!(y.contains("eth0"), "ethernet stays optional alongside wifi");
    }

    #[test]
    fn wifi_requires_credentials() {
        assert!(resolve_net(Link::Wifi, None, Some("x".into()), "PL".into()).is_err());
        assert!(resolve_net(Link::Wifi, Some("x".into()), None, "PL".into()).is_err());
    }

    #[test]
    fn yaml_quote_escapes() {
        assert_eq!(yaml_quote(r#"he"llo"#), r#""he\"llo""#);
        assert_eq!(yaml_quote(r#"a\b"#), r#""a\\b""#);
    }
}
