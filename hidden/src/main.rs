use bincode::config;
use bincode::de::read;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::{spawn, task};

use std::{env, vec};

use relay_shared::crypto::*;
use relay_shared::shared_consts::CONFIG_PORT;
use relay_shared::structs::{Connection, RelayConfig};

#[tokio::main]
async fn main() -> io::Result<()> {
    let ip = "127.0.0.1";

    // Encryption basic setup
    let (our_secret_key, our_public_key) = generate_keypair();
    let mut chacha_key: Option<[u8; 32]> = None;

    println!("Attempting to connect to config_port");
    let mut config_socket = TcpStream::connect(format!("{ip}:{CONFIG_PORT}")).await?;
    println!(
        "Connected to {}. This is the exposed server, and who is relaying messages to us.",
        config_socket.peer_addr()?
    );

    // Start with key exchange //
    let mut buf = [0u8; 1024];
    let relay_config = RelayConfig::KeyExchange(pubkey_to_bytes(&our_public_key));

    config_socket
        .write(&bincode::serialize(&relay_config).unwrap())
        .await?;

    let read_bytes = config_socket.read(&mut buf).await?;
    if read_bytes == 0 {
        println!("No bytes read from exposed server");
        println!("Exiting...");
        return Ok(());
    } else {
        if let RelayConfig::KeyExchange(received_key_bytes) =
            bincode::deserialize::<RelayConfig>(&buf[..read_bytes]).unwrap()
        {
            let their_public_key = pubkey_from_bytes(received_key_bytes.as_slice());
            let shared_secret = generate_shared_secret(&their_public_key, &our_secret_key);

            println!(
                "Arrived at shared secret: {}",
                shared_secret.display_secret()
            );
            chacha_key = Some(shared_secret.secret_bytes());
        } else {
            println!("Failed to deserialize key exchange message");
            return Ok(());
        }
    }

    // Set up our symmetric encryption
    let mut chacha_instance = get_chacha20(&chacha_key.unwrap());
    loop {
        let read_bytes = config_socket.read(&mut buf).await?;
        if read_bytes == 0 {
            println!("No bytes read from exposed server");
            println!("Exiting...");
            return Ok(());
        } else {
            let mut data = buf[..read_bytes].to_vec();
            decrypt_with_chacha(&mut chacha_instance, &mut data[..read_bytes]);
            let relay_config = bincode::deserialize::<RelayConfig>(&data[..read_bytes]).unwrap();
            println!("Received: {:?}", relay_config);
        }
    }

    Ok(())
}
