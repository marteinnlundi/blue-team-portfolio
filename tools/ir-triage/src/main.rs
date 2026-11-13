mod collectors;
mod manifest;
mod types;

use chrono::Utc;
use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use types::Report;

#[derive(Parser)]
#[command(
    name = "ir-triage",
    about = "Host triage — collect artifacts for incident response"
)]
struct Cli {
    #[arg(short, long, default_value = "triage-output")]
    output: PathBuf,

    #[arg(long, help = "Write report as pretty-printed JSON")]
    pretty: bool,
}

fn main() {
    let cli = Cli::parse();

    eprintln!("[ir-triage] Starting collection...");

    let host = collectors::host::collect();
    eprintln!("[ir-triage] Host info collected");

    let processes = collectors::process::collect();
    eprintln!("[ir-triage] {} processes collected", processes.len());

    let network = collectors::network::collect();
    eprintln!(
        "[ir-triage] {} connections, {} listening ports",
        network.connections.len(),
        network.listening_ports.len()
    );

    let users = collectors::users::collect();
    eprintln!(
        "[ir-triage] {} active sessions, {} auth events",
        users.active_sessions.len(),
        users.recent_auth_events.len()
    );

    let persistence = collectors::persistence::collect();
    eprintln!(
        "[ir-triage] {} services, {} cron entries",
        persistence.systemd_services.len(),
        persistence.cron_entries.len()
    );

    let log_slices = collectors::logs::collect();
    eprintln!("[ir-triage] {} log sources collected", log_slices.len());

    let sections: Vec<(&str, String)> = vec![
        ("host", serde_json::to_string(&host).unwrap_or_default()),
        (
            "processes",
            serde_json::to_string(&processes).unwrap_or_default(),
        ),
        (
            "network",
            serde_json::to_string(&network).unwrap_or_default(),
        ),
        ("users", serde_json::to_string(&users).unwrap_or_default()),
        (
            "persistence",
            serde_json::to_string(&persistence).unwrap_or_default(),
        ),
        (
            "logs",
            serde_json::to_string(&log_slices).unwrap_or_default(),
        ),
    ];

    let manifest_input: Vec<(&str, &str)> =
        sections.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let manifest: HashMap<String, String> = manifest::build_manifest(&manifest_input);

    let report = Report {
        schema_version: "1.0",
        collected_at: Utc::now(),
        host,
        processes,
        network,
        users,
        persistence,
        log_slices,
        manifest,
    };

    let json = if cli.pretty {
        serde_json::to_string_pretty(&report)
    } else {
        serde_json::to_string(&report)
    }
    .expect("serialization failed");

    fs::create_dir_all(&cli.output).expect("failed to create output directory");
    let report_path = cli.output.join("report.json");
    fs::write(&report_path, &json).expect("failed to write report");

    eprintln!("[ir-triage] Report written to {}", report_path.display());
    eprintln!("[ir-triage] Collection complete.");
}
