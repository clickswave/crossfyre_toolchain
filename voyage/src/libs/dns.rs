use hickory_resolver::{Resolver, TokioResolver};

/// Build a DNS resolver. With `dns_server = Some("1.1.1.1")` (a non-empty IP) it
/// queries that server explicitly; otherwise it falls back to the node host's
/// own resolver config (its default nameservers).
///
/// hickory-resolver 0.26 reshaped this API: `NameServerConfigGroup` is gone in
/// favour of building `NameServerConfig` values directly, and the Tokio
/// connection provider moved to `net::runtime::TokioRuntimeProvider`. The bump
/// was needed for two advisories that matter here, because this resolver parses
/// DNS responses from scan targets we do not control:
///   RUSTSEC-2026-0118  unbounded loop in NSEC3 closest-encloser validation
///   RUSTSEC-2026-0119  O(n^2) CPU exhaustion in message encoding
pub fn create_resolver(
    dns_server: Option<&str>,
) -> Result<TokioResolver, Box<dyn std::error::Error>> {
    match dns_server {
        Some(ip) if !ip.trim().is_empty() => {
            let ip = ip.trim();
            let addr: std::net::IpAddr = ip
                .parse()
                .map_err(|_| format!("invalid DNS server IP '{ip}'"))?;
            // udp_and_tcp keeps the previous behaviour: UDP first, TCP fallback
            // for responses that do not fit.
            let ns = hickory_resolver::config::NameServerConfig::udp_and_tcp(addr);
            let cfg = hickory_resolver::config::ResolverConfig::from_parts(None, vec![], vec![ns]);
            // 0.26: `build()` is fallible (it can fail to set up transports).
            Ok(Resolver::builder_with_config(
                cfg,
                hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
            )
            .build()?)
        }
        _ => Ok(Resolver::builder_tokio()?.build()?),
    }
}
