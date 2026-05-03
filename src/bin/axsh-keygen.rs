fn usage(program: &str) -> String {
    format!("usage: {program} <output-pkcs8-der-path>")
}

fn main() -> std::io::Result<()> {
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "axsh-keygen".to_string());
    let output = std::env::args()
        .nth(1)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, usage(&program)))?;
    let key = axsh::ConnSign::new().map_err(std::io::Error::other)?;
    key.write_to_file(&output).map_err(std::io::Error::other)?;
    println!("wrote {output}");
    Ok(())
}
