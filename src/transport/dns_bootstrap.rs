use std::net::SocketAddr;

use hickory_resolver::TokioResolver;

use crate::error::TesseraError;

/// Resolve bootstrap nodes via DNS SRV records.
/// Looks up `_tessera._udp.<domain>` and returns addresses sorted by SRV priority.
pub async fn resolve_bootstrap(
    domain: &str,
) -> Result<Vec<SocketAddr>, TesseraError> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| TesseraError::Network(format!("resolver init: {}", e)))?
        .build();

    let srv_name = format!("_tessera._udp.{}", domain);

    let srv_lookup = resolver.srv_lookup(&srv_name).await.map_err(|e| {
        TesseraError::Network(format!("DNS SRV lookup failed: {}", e))
    })?;

    let mut entries: Vec<(u16, String, u16)> = Vec::new();
    for record in srv_lookup.iter() {
        entries.push((
            record.priority(),
            record.target().to_string(),
            record.port(),
        ));
    }

    // Sort by priority (lower = higher priority)
    entries.sort_by_key(|(priority, _, _)| *priority);

    let mut addrs = Vec::new();
    for (_, target, port) in &entries {
        match resolver.lookup_ip(target.as_str()).await {
            Ok(ips) => {
                for ip in ips.iter() {
                    addrs.push(SocketAddr::new(ip, *port));
                }
            }
            Err(e) => {
                tracing::warn!("failed to resolve {}: {}", target, e);
            }
        }
    }

    Ok(addrs)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_srv_name_format() {
        let domain = "example.com";
        let srv_name = format!("_tessera._udp.{}", domain);
        assert_eq!(srv_name, "_tessera._udp.example.com");
    }
}
