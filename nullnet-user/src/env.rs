pub static ETH_NAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("ETH_NAME").unwrap_or_else(|_| {
        println!("'ETH_NAME' environment variable not set");
        "ens18".to_string()
    })
});
