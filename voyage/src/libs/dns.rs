use hickory_resolver::{Resolver, TokioResolver};

pub fn create_resolver() -> Result<TokioResolver, Box<dyn std::error::Error>> {
    Ok(Resolver::builder_tokio()?.build())
}
