use std::collections::HashSet;
use reqwest::Client;
use serde::Deserialize;

#[derive(Deserialize)]
struct Response {
    name_value: String,
}

pub async fn fetch(
    reqwest_client: &Client,
    domain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut results = vec![];

    let url = format!("https://crt.sh/?q={}&output=json", domain);
    let response = reqwest_client.get(&url).send().await?;

    if response.status().is_success() {
        let body: Vec<Response> = response.json().await?;
        let mut unique_subdomains = HashSet::new();
        // crt.sh packs every SAN of a cert into one newline-separated
        // name_value, so split it into individual hostnames before parsing.
        let dot_suffix = format!(".{}", domain);
        for entry in body {
            for raw in entry.name_value.split(['\n', '\r']) {
                let host = raw.trim().trim_start_matches("*.").to_lowercase();
                if host.is_empty() {
                    continue;
                }
                // Keep only real subdomains of the target (skip the apex and
                // unrelated names like "notgoogle.com" that merely end in it).
                if let Some(stripped) = host.strip_suffix(&dot_suffix) {
                    if !stripped.is_empty() && stripped != "*" {
                        unique_subdomains.insert(stripped.to_string());
                    }
                }
            }
        }
        results.extend(unique_subdomains.into_iter());
    }

    Ok(results)
}
