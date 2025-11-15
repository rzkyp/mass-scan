use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead, Write}; // ← tambahkan Write
use std::process::Command;

#[derive(Serialize, Deserialize, Debug)]
struct Report {
    target: String,
    timestamp: DateTime<Utc>,
    engine: Engine,
    findings: Vec<Finding>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum Engine {
    Xss,
    Sqli,
    Nuclei,
}

#[derive(Serialize, Deserialize, Debug)]
struct Finding {
    url: String,
    payload: String,
    evidence: String,
    severity: String,
    extra: serde_json::Value,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("hasil-scan")?;
    let urls: Vec<String> = if let Some(file) = std::env::args().nth(1) {
        std::fs::read_to_string(file)?
            .lines()
            .filter(|l| l.contains("FUZZ"))
            .map(String::from)
            .collect()
    } else {
        io::stdin()
            .lock()
            .lines()
            .filter_map(Result::ok)
            .filter(|l| l.contains("FUZZ"))
            .collect()
    };

    if urls.is_empty() {
        eprintln!("[!] Tidak ada URL dengan token FUZZ");
        return Ok(());
    }

    println!("[+] Memulai XSS scan …");
    let xss = run_xss(&urls)?;
    write_report(&xss, "hasil-scan/hasil-xss.txt")?;

    println!("[+] Memulai SQLi scan …");
    let sqli = run_sqli(&urls)?;
    write_report(&sqli, "hasil-scan/hasil-sqli.txt")?;

    println!("[+] Memulai Nuclei scan …");
    let nuclei = run_nuclei(&urls)?;
    write_report(&nuclei, "hasil-scan/hasil-nuclei.txt")?;

    println!("[+] Selesai! Lihat hasil-scan/");
    Ok(())
}

/* ----------------------------------------------------------
 *  XSS – dalfox JSON
 * ---------------------------------------------------------- */
fn run_xss(urls: &[String]) -> Result<Report, Box<dyn std::error::Error>> {
    let mut findings = vec![];
    for url in urls {
        let injected = url.replace("FUZZ", "<script>alert(1)</script>");
        let out = Command::new("dalfox")
            .args(&["url", &injected, "--format", "json", "--only-poc"])
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&stdout) {
            for poc in arr.as_array().unwrap_or(&vec![]) {
                findings.push(Finding {
                    url: injected.clone(),
                    payload: "<script>alert(1)</script>".into(),
                    evidence: poc["poc"].as_str().unwrap_or("").into(),
                    severity: "high".into(),
                    extra: serde_json::json!({
                        "dalfox_poc": poc["poc"],
                        "curl_poc":   poc["curl-poc"],
                        "cve":        poc["cve-id"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    }),
                });
            }
        }
    }
    Ok(Report {
        target: urls.join(", "),
        timestamp: Utc::now(),
        engine: Engine::Xss,
        findings,
    })
}

/* ----------------------------------------------------------
 *  SQLi – sqlmap JSON
 * ---------------------------------------------------------- */
fn run_sqli(urls: &[String]) -> Result<Report, Box<dyn std::error::Error>> {
    let mut findings = vec![];
    for url in urls {
        let injected = url.replace("FUZZ", "*");
        let tmp = "hasil-scan/sqli-tmp";
        let _ = fs::create_dir_all(tmp);
        let out = Command::new("sqlmap")
            .args(&[
                "-u", &injected,
                "--batch", "--level=1", "--risk=1",
                "--format", "JSON",
                "--output-dir", tmp,
            ])
            .output()?;
        let log_file = format!("{}/log", tmp);
        if let Ok(json_str) = fs::read_to_string(&log_file) {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&json_str) {
                if let Some(data) = obj.get("data").and_then(|d| d.as_array()) {
                    for row in data {
                        findings.push(Finding {
                            url: injected.clone(),
                            payload: row["payload"].as_str().unwrap_or("*").into(),
                            evidence: row["title"].as_str().unwrap_or("").into(),
                            severity: "high".into(),
                            extra: serde_json::json!({
                                "dbms":     row["dbms"],
                                "db_name":  row["db"],
                                "user":     row["user"],
                                "password": row["password"],
                                "tables":   row["tables"],
                                "cve":      row["cve"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                            }),
                        });
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(tmp);
    }
    Ok(Report {
        target: urls.join(", "),
        timestamp: Utc::now(),
        engine: Engine::Sqli,
        findings,
    })
}

/* ----------------------------------------------------------
 *  Nuclei – JSON lines
 * ---------------------------------------------------------- */
fn run_nuclei(urls: &[String]) -> Result<Report, Box<dyn std::error::Error>> {
    let mut findings = vec![];
    let input = "hasil-scan/nuclei-input.txt";
    fs::write(input, urls.join("\n"))?;
    let out = Command::new("nuclei")
        .args(&["-l", input, "-json"])
        .output()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) {
            findings.push(Finding {
                url: obj["matched-at"].as_str().unwrap_or("").into(),
                payload: obj["template-id"].as_str().unwrap_or("").into(),
                evidence: obj["matcher-name"].as_str().unwrap_or("").into(),
                severity: obj["info"]["severity"].as_str().unwrap_or("info").into(),
                extra: serde_json::json!({
                    "template_id": obj["template-id"],
                    "name":        obj["info"]["name"],
                    "description": obj["info"]["description"],
                    "cve":         obj["info"]["classification"]["cve-id"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                }),
            });
        }
    }
    let _ = fs::remove_file(input);
    Ok(Report {
        target: urls.join(", "),
        timestamp: Utc::now(),
        engine: Engine::Nuclei,
        findings,
    })
}

/* ----------------------------------------------------------
 *  REPORT WRITER (pretty + JSON)
 * ---------------------------------------------------------- */
fn write_report(report: &Report, file_name: &str) -> std::io::Result<()> {
    let pretty = serde_json::to_string_pretty(&report)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(file_name)?;

    writeln!(file, "🦀 mass-scan – {:?} report", report.engine)?;
    writeln!(file, "📅 {}", report.timestamp.format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "🎯 Target: {}", report.target)?;
    writeln!(file, "{}", "─".repeat(70))?;

    for (i, f) in report.findings.iter().enumerate() {
        writeln!(file, "\n🔍 Finding #{}", i + 1)?;
        writeln!(file, "   URL      : {}", f.url)?;
        writeln!(file, "   Payload  : {}", f.payload)?;
        writeln!(file, "   Evidence : {}", f.evidence)?;
        writeln!(file, "   Severity : {}", f.severity)?;
        if !f.extra.is_null() {
            writeln!(file, "   Extra    : {}", serde_json::to_string_pretty(&f.extra)?)?;
        }
    }
    writeln!(file, "\n{}\n", "─".repeat(70))?;
    writeln!(file, "📦 JSON raw:\n{}\n", pretty)?;
    Ok(())
}
