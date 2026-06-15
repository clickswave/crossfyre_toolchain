use crate::scanners::techniques;
use hickory_resolver::TokioResolver;
use reqwest::Client;

pub struct NegativeResult {
    pub level: String,
    pub description: String,
}

pub struct ActiveScanResult {
    pub found: bool,
    pub source: String,
    pub negatives: Vec<NegativeResult>,
}

pub async fn execute(
    resolver: &TokioResolver,
    reqwest_client: &Client,
    exclude_techniques: &[String],
    http_probing_ports: &[u16],
    https_probing_ports: &[u16],
    full_subdomain: &str,
) -> ActiveScanResult {
    let domain = full_subdomain.to_string();
    let mut scan_result = ActiveScanResult {
        found: false,
        source: String::new(),
        negatives: vec![],
    };

    // ipv4 lookup
    if !exclude_techniques.contains(&"ipv4_lookup".to_string()) {
        let ipv4_lookup = techniques::ipv4_lookup::execute(resolver, &domain).await;
        match ipv4_lookup {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = "ipv4_lookup".to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.push(e),
        }
    }

    // ipv6 lookup
    if !exclude_techniques.contains(&"ipv6_lookup".to_string()) {
        let ipv6_lookup = techniques::ipv6_lookup::execute(resolver, &domain).await;
        match ipv6_lookup {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = "ipv6_lookup".to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.push(e),
        }
    }

    // http probing
    if !exclude_techniques.contains(&"http_probing".to_string()) {
        let http_probing =
            techniques::http_probing::execute(reqwest_client, &domain, http_probing_ports).await;
        match http_probing {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = "http_probing".to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.extend(e),
        }
    }

    // https probing
    if !exclude_techniques.contains(&"https_probing".to_string()) {
        let https_probing =
            techniques::https_probing::execute(reqwest_client, &domain, https_probing_ports).await;
        match https_probing {
            Ok(_) => {
                scan_result.found = true;
                scan_result.source = "https_probing".to_string();
                return scan_result;
            }
            Err(e) => scan_result.negatives.extend(e),
        }
    }

    scan_result
}
