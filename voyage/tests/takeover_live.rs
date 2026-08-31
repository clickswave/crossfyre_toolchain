//! Live DNS checks for the takeover engine.
//!
//! `#[ignore]` by default: these resolve real names, so they belong to a human
//! running `cargo test -p voyage -- --ignored --nocapture`, not to CI, where a
//! network blip would read as a code failure.
//!
//! What they are actually for is the false-positive side. The logic that decides
//! "this record points into nothing" runs against strangers' domains and gets
//! published, so being wrong is expensive. A healthy domain must come back clean.

// The crate is a binary, so the module is included directly rather than imported.
#[path = "../src/takeover.rs"]
mod takeover;

#[path = "../src/libs/dns.rs"]
mod dns;

async fn no_fetch(_host: String) -> Option<String> {
    // DNS-only: these cases must be decided without an HTTP request at all.
    None
}

#[tokio::test]
#[ignore]
async fn healthy_hosts_are_not_flagged() {
    let resolver = dns::create_resolver(Some("1.1.1.1")).expect("resolver");

    // Live, well-maintained hosts. Any finding here is a false positive, which
    // is the failure mode that matters most for a public tool.
    for host in ["www.google.com", "github.com", "www.cloudflare.com"] {
        let r = takeover::check(&resolver, host, no_fetch).await;
        assert!(
            !r.is_finding(),
            "false positive on {host}: {:?} / {}",
            r.verdict,
            r.detail
        );
    }
}

#[tokio::test]
#[ignore]
async fn a_name_that_does_not_exist_is_not_reported_as_dangling() {
    let resolver = dns::create_resolver(Some("1.1.1.1")).expect("resolver");

    // The host itself is NXDOMAIN, but it has no CNAME, so there is no dangling
    // record. Reporting this would flag every typo anyone ever pasted into the
    // form as a takeover.
    let r = takeover::check(
        &resolver,
        "this-name-should-never-exist-cfx-test.example.com",
        no_fetch,
    )
    .await;
    assert!(!r.is_finding(), "flagged a plain NXDOMAIN host: {}", r.detail);
    assert_eq!(r.verdict, takeover::Verdict::Clean);
}

#[tokio::test]
#[ignore]
async fn a_cname_to_a_live_provider_is_claimed_not_dangling() {
    let resolver = dns::create_resolver(Some("1.1.1.1")).expect("resolver");

    // docs.github.com CNAMEs into GitHub's own infrastructure and is very much
    // being served. It must not read as a takeover just because the chain ends
    // at a recognised provider.
    let r = takeover::check(&resolver, "docs.github.com", no_fetch).await;
    assert_ne!(
        r.verdict,
        takeover::Verdict::DanglingNxdomain,
        "live host reported as dangling: {}",
        r.detail
    );
}
