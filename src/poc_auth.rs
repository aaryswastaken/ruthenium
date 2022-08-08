use reqwest::blocking::Client;

fn main() {
    let client = Client::new();

    let res = client
        .post("https://plex.tv/users/sign_in.xml")
        .header("X-Plex-Device", "RutheniumProxy")
        .header("X-Plex-Model", "2,3")
        .header("X-Plex-Client-Identifier", "001")
        .header("X-Plex-Platform", "Rust")
        .header("X-Plex-Client-Platform", "Rust")
        .header("X-Plex-Client-Profile-Extra", "add-transcode-target(type=MusicProfile&context=streaming&protocol=hls&container=mpegts&audioCodec=aac)+add-transcode-target(type=videoProfile&context=streaming&protocol=hls&container=mpegts&videoCodec=h264&audioCodec=aac,mp3&replace=true)")
        .header("X-Plex-Product", "PlexConnect")
        .header("X-Plex-Version", "1.0.0")
        .basic_auth(" --- redacted --- ", Some(" --- redacted --- ".to_string()))
        .send();
    
    match res {
        Ok(response) => {
            if response.status().is_success() {
                println!("Ok")
            } else {
                println!("Request status: {}", response.status());
            }
        },
        Err(e) => println!("{}", e)
    }
}