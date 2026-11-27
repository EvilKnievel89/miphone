//! DNS SRV lookup of the SIP server, as the Mitel client does it when a profile gives port 0.

use std::ptr;
use windows_sys::Win32::NetworkManagement::Dns::{DNS_QUERY_STANDARD, DNS_RECORDW, DNS_TYPE_SRV, DnsFree, DnsFreeRecordList, DnsQuery_W};

/// Port of SIP over TLS if DNS names none.
pub const DEFAULT_TLS_PORT: u16 = 5061;

/// One server a SRV record points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

/// The servers for SIP over TLS at `domain` (`_sips._tcp.<domain>`), the one to try first in
/// front. Without such records the domain itself is the server, at the default port.
pub async fn sip_tls_servers(domain: &str) -> Vec<(String, u16)> {
    let name = format!("_sips._tcp.{domain}");
    let found = tokio::task::spawn_blocking(move || query_srv(&name)).await.unwrap_or_default();
    match order(found) {
        targets if targets.is_empty() => vec![(domain.to_string(), DEFAULT_TLS_PORT)],
        targets => targets.into_iter().map(|t| (t.host, t.port)).collect(),
    }
}

/// Lowest priority first, among equals the highest weight, like the Mitel client.
fn order(mut targets: Vec<Target>) -> Vec<Target> {
    // A single record with the target "." says that the service is not offered.
    targets.retain(|t| !t.host.is_empty() && t.host != "." && t.port != 0);
    targets.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));
    targets
}

/// Asks the system's resolver; no answer and an error both give an empty list.
fn query_srv(name: &str) -> Vec<Target> {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut records: *mut DNS_RECORDW = ptr::null_mut();
    // SAFETY: `wide` is a terminated string that outlives the call; the list the resolver
    // hands out is only read before it is freed below.
    unsafe {
        let status = DnsQuery_W(wide.as_ptr(), DNS_TYPE_SRV, DNS_QUERY_STANDARD, ptr::null_mut(), (&raw mut records).cast(), ptr::null_mut());
        let mut targets = Vec::new();
        if status == 0 {
            let mut next = records;
            while let Some(record) = next.as_ref() {
                if record.wType == DNS_TYPE_SRV {
                    let srv = record.Data.SRV;
                    if !srv.pNameTarget.is_null() {
                        let len = (0..).take_while(|&i| *srv.pNameTarget.add(i) != 0).count();
                        let host = String::from_utf16_lossy(std::slice::from_raw_parts(srv.pNameTarget, len));
                        targets.push(Target { host: host.trim_end_matches('.').to_string(), port: srv.wPort, priority: srv.wPriority, weight: srv.wWeight });
                    }
                }
                next = record.pNext;
            }
        }
        if !records.is_null() {
            DnsFree(records.cast(), DnsFreeRecordList);
        }
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, port: u16, priority: u16, weight: u16) -> Target {
        Target { host: host.into(), port, priority, weight }
    }

    #[test]
    fn orders_by_priority_then_weight() {
        let ordered = order(vec![target("c", 5061, 20, 90), target("b", 5061, 10, 10), target("a", 5063, 10, 60), target(".", 0, 0, 0)]);
        assert_eq!(ordered.iter().map(|t| (t.host.as_str(), t.port)).collect::<Vec<_>>(), [("a", 5063), ("b", 5061), ("c", 5061)]);
    }

    /// Needs the network: reads SRV records that are known to exist.
    #[test]
    #[ignore]
    fn reads_real_records() {
        let targets = query_srv("_xmpp-server._tcp.jabber.org");
        println!("{targets:?}");
        assert!(targets.iter().all(|t| !t.host.is_empty() && t.port != 0) && !targets.is_empty());
    }

    #[tokio::test]
    async fn falls_back_to_the_domain_itself() {
        // `.invalid` never resolves (RFC 2606).
        assert_eq!(sip_tls_servers("nothing.invalid").await, [("nothing.invalid".to_string(), 5061)]);
    }
}
