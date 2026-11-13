use crate::types::{ListeningPort, NetworkConnection, NetworkSnapshot};
use std::fs;
use std::net::Ipv6Addr;

pub fn collect() -> NetworkSnapshot {
    let connections: Vec<NetworkConnection> = parse_tcp("/proc/net/tcp")
        .into_iter()
        .chain(parse_tcp("/proc/net/tcp6"))
        .chain(parse_udp("/proc/net/udp"))
        .chain(parse_udp("/proc/net/udp6"))
        .collect();

    let listening_ports = extract_listening(&connections);

    NetworkSnapshot {
        connections,
        listening_ports,
    }
}

fn hex_to_ipv4(hex: &str) -> String {
    if hex.len() != 8 {
        return hex.to_string();
    }
    let n = u32::from_str_radix(hex, 16).unwrap_or(0);
    let b = n.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Decode an address from /proc/net/tcp6: four 32-bit words, each printed in
/// host byte order (little-endian on the platforms this tool targets).
fn hex_to_ipv6(hex: &str) -> String {
    if hex.len() != 32 || !hex.is_ascii() {
        return hex.to_string();
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let chunk = &hex[word * 8..word * 8 + 8];
        let n = u32::from_str_radix(chunk, 16).unwrap_or(0);
        bytes[word * 4..word * 4 + 4].copy_from_slice(&n.to_le_bytes());
    }
    let addr = Ipv6Addr::from(bytes);
    match addr.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => addr.to_string(),
    }
}

fn hex_addr_port(raw: &str) -> (String, u16) {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 2 {
        return (raw.to_string(), 0);
    }
    let ip = match parts[0].len() {
        8 => hex_to_ipv4(parts[0]),
        32 => hex_to_ipv6(parts[0]),
        _ => parts[0].to_string(),
    };
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    (ip, port)
}

/// "192.0.2.1:22" or "[2001:db8::1]:22".
fn join_addr(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    }
}

fn tcp_state(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn parse_tcp(path: &str) -> Vec<NetworkConnection> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 12 {
                return None;
            }
            let (local_ip, local_port) = hex_addr_port(cols[1]);
            let (remote_ip, remote_port) = hex_addr_port(cols[2]);
            let state = tcp_state(cols[3]).to_string();
            Some(NetworkConnection {
                protocol: "tcp".to_string(),
                local_addr: join_addr(&local_ip, local_port),
                remote_addr: join_addr(&remote_ip, remote_port),
                state,
                pid: None,
            })
        })
        .collect()
}

fn parse_udp(path: &str) -> Vec<NetworkConnection> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                return None;
            }
            let (local_ip, local_port) = hex_addr_port(cols[1]);
            let (remote_ip, remote_port) = hex_addr_port(cols[2]);
            Some(NetworkConnection {
                protocol: "udp".to_string(),
                local_addr: join_addr(&local_ip, local_port),
                remote_addr: join_addr(&remote_ip, remote_port),
                state: "UDP".to_string(),
                pid: None,
            })
        })
        .collect()
}

fn extract_listening(conns: &[NetworkConnection]) -> Vec<ListeningPort> {
    conns
        .iter()
        .filter(|c| c.state == "LISTEN")
        .filter_map(|c| {
            let parts: Vec<&str> = c.local_addr.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                return None;
            }
            let port = parts[0].parse::<u16>().ok()?;
            Some(ListeningPort {
                protocol: c.protocol.clone(),
                address: parts[1].to_string(),
                port,
                pid: c.pid,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_snapshot() {
        let snap = collect();
        let _ = snap.connections.len() + snap.listening_ports.len();
    }

    #[test]
    fn hex_to_ipv4_converts_correctly() {
        assert_eq!(hex_to_ipv4("0101A8C0"), "192.168.1.1");
        assert_eq!(hex_to_ipv4("0100007F"), "127.0.0.1");
    }

    #[test]
    fn hex_addr_port_splits_correctly() {
        let (ip, port) = hex_addr_port("0100007F:0035");
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn hex_to_ipv6_converts_correctly() {
        assert_eq!(hex_to_ipv6("00000000000000000000000001000000"), "::1");
        assert_eq!(
            hex_to_ipv6("B80D0120000000000000000001000000"),
            "2001:db8::1"
        );
        // IPv4-mapped addresses are shown as plain IPv4.
        assert_eq!(hex_to_ipv6("0000000000000000FFFF00000100007F"), "127.0.0.1");
        // Anything unexpected is passed through untouched.
        assert_eq!(hex_to_ipv6("xyz"), "xyz");
    }

    #[test]
    fn ipv6_addresses_are_bracketed() {
        let (ip, port) = hex_addr_port("00000000000000000000000000000000:0016");
        assert_eq!(join_addr(&ip, port), "[::]:22");
        assert_eq!(join_addr("0.0.0.0", 22), "0.0.0.0:22");
    }
}
