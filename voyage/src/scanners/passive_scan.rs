use std::collections::HashMap;

pub async fn execute(
    domain: &str,
    user_agent: &str,
    exclude_sources: &[String],
) -> Result<HashMap<String, String>, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let mut results: HashMap<String, String> = HashMap::new();

    // crt.sh - returns subdomain prefixes, reconstruct full subdomains
    if !exclude_sources.contains(&"crt.sh".to_string()) {
        match crate::scanners::providers::crt_sh::fetch(&client, domain).await {
            Ok(prefixes) => {
                for prefix in prefixes {
                    results.insert(format!("{}.{}", prefix, domain), "crt.sh".to_string());
                }
            }
            Err(e) => eprintln!("[WARN] crt.sh error: {}", e),
        }
    }

    // hackertarget - returns subdomain prefixes, reconstruct full subdomains
    if !exclude_sources.contains(&"hackertarget".to_string()) {
        match crate::scanners::providers::hackertarget::fetch(&client, domain).await {
            Ok(prefixes) => {
                for prefix in prefixes {
                    results.insert(format!("{}.{}", prefix, domain), "hackertarget".to_string());
                }
            }
            Err(e) => eprintln!("[WARN] hackertarget error: {}", e),
        }
    }

    // alienvault - returns full subdomains directly
    if !exclude_sources.contains(&"alienvault".to_string()) {
        match crate::scanners::providers::alienvault::fetch(&client, domain).await {
            Ok(full_subdomains) => {
                for subdomain in full_subdomains {
                    results.insert(subdomain, "alienvault".to_string());
                }
            }
            Err(e) => eprintln!("[WARN] alienvault error: {}", e),
        }
    }

    Ok(results)
}
