use hickory_resolver::{Resolver, TokioResolver};

/// Build a DNS resolver. With `dns_server = Some("1.1.1.1")` (a non-empty IP) it
/// queries that server explicitly; otherwise it falls back to the node host's
/// own resolver config (its default nameservers).
pub fn create_resolver(dns_server: Option<&str>) -> Result<TokioResolver, Box<dyn std::error::Error>> {
    match dns_server {
        Some(ip) if !ip.trim().is_empty() => {
            let ip = ip.trim();
            let addr: std::net::IpAddr = ip
                .parse()
                .map_err(|_| format!("invalid DNS server IP '{}'", ip))?;
            let group =
                hickory_resolver::config::NameServerConfigGroup::from_ips_clear(&[addr], 53, true);
            let cfg = hickory_resolver::config::ResolverConfig::from_parts(None, vec![], group);
            Ok(Resolver::builder_with_config(
                cfg,
                hickory_resolver::name_server::TokioConnectionProvider::default(),
            )
            .build())
        }
        _ => Ok(Resolver::builder_tokio()?.build()),
    }
}
