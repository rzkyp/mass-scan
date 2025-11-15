use anyhow::{Context, Result};
use clap::Parser;
use rayon::prelude::*;
use std::{
    fs,
    io::{self, BufRead},
    path::Path,
    process::Command,
};

/// Mass XSS + SQLi + Nuclei scanner (ganti FUZZ → payload)
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Mass XSS + SQLi + Nuclei scanner",
    long_about = r#"
EXAMPLES:
  mass-scan              # scan semua (stdin)
  mass-scan -x           # XSS saja
  mass-scan -s           # SQLi saja
  mass-scan -n           # Nuclei saja
  mass-scan file.txt     # pakai file
  mass-scan -u example.com  # scan satu URL (harus ada FUZZ)
"#
)]
struct Args {
    /// File berisi daftar URL (atau stdin kalau tidak ada)
    file: Option<String>,

    /// Scan satu URL saja
    #[arg(short, long)]
    url: Option<String>,

    /// XSS only
    #[arg(short, long)]
    xss: bool,

    /// SQLi only
    #[arg(short, long)]
    sqli: bool,

    /// Nuclei only
    #[arg(short, long)]
    nuc: bool,
}

const OUT_DIR: &str = "hasil-scan";
const XSS_PAY: &str = "<script>alert(1)</script>";

fn load_urls(args: &Args) -> Result<Vec<String>> {
    let list = if let Some(u) = &args.url {
        vec![u.clone()]
    } else if let Some(f) = &args.file {
        let file = fs::File::open(f)?;
        io::BufReader::new(file)
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| l.contains("FUZZ"))
            .collect()
    } else {
        io::stdin()
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| l.contains("FUZZ"))
            .collect()
    };
    Ok(list)
}

fn ensure_out() -> Result<()> {
    fs::create_dir_all(OUT_DIR)?;
    Ok(())
}

fn build_xss(urls: &[String]) -> Result<String> {
    let p = Path::new(OUT_DIR).join("xss-urls.txt");
    let c = urls.par_iter().map(|u| u.replace("FUZZ", XSS_PAY)).collect::<Vec<_>>().join("\n");
    fs::write(&p, c)?;
    Ok(p.to_string_lossy().into_owned())
}

fn run_dalfox(xss_file: &str) -> Result<()> {
    let out = Path::new(OUT_DIR).join("xss-findings.txt");
    Command::new("dalfox")
        .args(&["file", xss_file, "--only-poc", "--output"])
        .arg(&out)
        .status()
        .context("dalfox error")?;
    println!("[+] XSS selesai → {}", out.display());
    Ok(())
}

fn build_sqli(urls: &[String]) -> Result<String> {
    let p = Path::new(OUT_DIR).join("sqli-urls.txt");
    let c = urls.par_iter().map(|u| u.replace("FUZZ", "*")).collect::<Vec<_>>().join("\n");
    fs::write(&p, c)?;
    Ok(p.to_string_lossy().into_owned())
}

fn run_sqlmap(sqli_file: &str) -> Result<()> {
    Command::new("sqlmap")
        .args(&["-m", sqli_file, "--batch", "--level=1", "--risk=1", "--output-dir", OUT_DIR])
        .status()
        .context("sqlmap error")?;
    println!("[+] SQLi selesai → folder {}", OUT_DIR);
    Ok(())
}

fn run_nuclei(urls: &[String]) -> Result<()> {
    let raw = Path::new(OUT_DIR).join("raw.txt");
    fs::write(&raw, urls.join("\n"))?;
    let out = Path::new(OUT_DIR).join("nuclei-findings.txt");
    Command::new("nuclei")
        .args(&["-l", raw.to_str().unwrap(), "-t", "http/vulnerabilities/", "-o", out.to_str().unwrap()])
        .status()
        .context("nuclei error")?;
    println!("[+] Nuclei selesai → {}", out.display());
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure_out()?;
    let urls = load_urls(&args)?;
    if urls.is_empty() {
        eprintln!("[!] Tidak ada URL dengan FUZZ");
        return Ok(());
    }
    let (x, s, n) = if !args.xss && !args.sqli && !args.nuc {
        (true, true, true)
    } else {
        (args.xss, args.sqli, args.nuc)
    };
    if x {
        let f = build_xss(&urls)?;
        run_dalfox(&f)?;
    }
    if s {
        let f = build_sqli(&urls)?;
        run_sqlmap(&f)?;
    }
    if n {
        run_nuclei(&urls)?;
    }
    println!("\n[+] Selesai! Cek {}", OUT_DIR);
    Ok(())
}
