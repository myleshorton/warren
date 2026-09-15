//! Inspect native locale selection without opening network sockets.
use warren::community::Community;

fn main() -> std::io::Result<()> {
    let explicit = std::env::args()
        .nth(1)
        .map(|locale| {
            Community::from_locale(&locale).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid language tag")
            })
        })
        .transpose()?;
    let choice = Community::detect(explicit.as_ref(), None, None)?;
    println!(
        "Language: {}",
        choice.language().unwrap_or("custom invitation")
    );
    println!("Community: {:?}", choice.overlay());
    Ok(())
}
