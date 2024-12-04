use bincode::config;
use serde::Serialize;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::{spawn, task};

use std::{env, vec};

use relay_shared::crypto::*;
use relay_shared::shared_consts::{CONFIG_PORT, EXPOSED_SERVER_PORT};
use relay_shared::structs::{Connection, RelayConfig};

#[tokio::main]
async fn main() -> io::Result<()> {
    let ip = "127.0.0.1";

    // Encryption basic setup
    let (our_secret_key, our_public_key) = generate_keypair();
    let mut chacha_key: Option<[u8; 32]> = None;

    println!("Starting config server on port: {}", CONFIG_PORT);
    let _config_listener = TcpListener::bind(format!("{ip}:{CONFIG_PORT}")).await?;
    let (mut config_socket, _) = _config_listener.accept().await?;
    println!(
        "Accepted connection from: {}. This is the hidden server, and who we're relaying messages to.",
        config_socket.peer_addr()?
    );

    // PREPARE ENCRYPTION
    let mut buf = [0u8; 1024];
    let read_bytes = config_socket.read(&mut buf).await?;
    if read_bytes == 0 {
        println!("No bytes read from hidden server");
        println!("Exiting...");
        return Ok(());
    } else {
        if let RelayConfig::KeyExchange(received_key_bytes) =
            bincode::deserialize::<RelayConfig>(&buf[..read_bytes]).unwrap()
        {
            // We now need to exchange keys
            let their_public_key = pubkey_from_bytes(received_key_bytes.as_slice());
            let shared_secret = generate_shared_secret(&their_public_key, &our_secret_key);

            // Send our public key to the hidden server
            let relay_config = RelayConfig::KeyExchange(pubkey_to_bytes(&our_public_key));
            config_socket
                .write(&bincode::serialize(&relay_config).unwrap())
                .await?;
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

    // Setup our symmetric encryption
    let mut chacha_instance = get_chacha20(&chacha_key.unwrap());

    let _data_listener = TcpListener::bind(format!("{ip}:{EXPOSED_SERVER_PORT}")).await?;
    loop {
        // Get incoming connections
        let (mut incoming_socket, incoming_connection_details) = _data_listener.accept().await?;
        let connection_details = Connection {
            incoming_port: incoming_connection_details.port(),
            incoming_addr: incoming_connection_details.ip().to_string(),
        };

        // Tell the hidden server about the new connection
        // This is our relay port
        let _relay_listener = TcpListener::bind("127.0.0.1:0").await?;
        let relay_port = _relay_listener.local_addr().unwrap().port();

        let relay_config =
            RelayConfig::NewConnection(relay_port, String::new(), connection_details);

        // Write the relay config to the hidden server
        config_socket
            .write(
                apply_keystream_and_return_new(
                    &mut chacha_instance,
                    &mut bincode::serialize(&relay_config).unwrap(),
                )
                .as_slice(),
            )
            .await?;
    }

    Ok(())
}

async fn handle_socket(socket: TcpStream) -> io::Result<()> {
    let mut buf = [0; 1024];
    let mut socket = socket;

    loop {
        let n = socket.read(&mut buf).await?;

        if n == 0 {
            return Ok(());
        }

        let received_string = String::from_utf8(buf[..n].to_vec()).unwrap();
        print!("{} says: {}", socket.peer_addr().unwrap(), received_string);
    }
    println!("{} disconnected", socket.peer_addr().unwrap());
}
