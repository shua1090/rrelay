use clap::Parser;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::{select, spawn};

use relay_shared::crypto::*;
use relay_shared::structs::{HiddenCmdOptions, RelayConfig};

#[tokio::main]
async fn main() -> io::Result<()> {
    let cmdline_options = HiddenCmdOptions::parse();
    let relay_ip = cmdline_options.relay_ip;
    let config_port = cmdline_options.config_port;
    let target_port = cmdline_options.target_port;

    // Encryption basic setup
    let (our_secret_key, our_public_key) = generate_keypair();
    let mut chacha_key: Option<[u8; 32]> = None;

    println!(
        "Attempting to connect to relay server at: {}:{}",
        relay_ip, config_port
    );
    let mut config_socket = TcpStream::connect(format!("{relay_ip}:{config_port}")).await?;
    println!(
        "Connected to {}. This is the exposed server, and who is relaying messages to us.",
        config_socket.peer_addr()?
    );

    // Start with key exchange //
    let mut buf = [0u8; 1024];
    let relay_config = RelayConfig::KeyExchange(pubkey_to_bytes(&our_public_key));

    config_socket
        .write_all(&bincode::serialize(&relay_config).unwrap())
        .await?;

    let read_bytes = config_socket.read(&mut buf).await?;
    if read_bytes == 0 {
        println!("No bytes read from exposed server");
        println!("Exiting...");
        return Ok(());
    } else if let RelayConfig::KeyExchange(received_key_bytes) =
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

            // If we got a new connection, we open up a port
            // to the relay (exposed server) and connect to it
            if let RelayConfig::NewConnection(port, uuid, connection) = relay_config {
                println!(
                    "Received connection relay from: {}",
                    connection.incoming_addr
                );

                let incoming_socket = TcpStream::connect(format!("{relay_ip}:{port}")).await?;
                spawn(handle_connection(incoming_socket, uuid, target_port));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Received invalid message; expected NewConnection",
                ));
            }
        }
    }
}

/**
 * This function handles the connection between the relay and the hidden server.
 * It reads from the relay, decrypts the message, and sends it to the target server.
 * It also reads from the target server, encrypts the message, and sends it to the relay.
 */
async fn handle_connection(
    mut relay_socket: TcpStream,
    uuid: [u8; 32],
    target_port: u16,
) -> io::Result<()> {
    // This is the target server, the place
    // that we want to reach all along, but because of the dreaded
    // NAT we can't reach it directly
    let mut target_socket = TcpStream::connect(format!("127.0.0.1:{}", target_port)).await?;

    // This cipher is used to send to the hidden server
    let mut relay_cipher_send = get_chacha20(&uuid);
    // We use this cipher to decrypt what we receive from the hidden server
    let mut relay_cipher_recv = get_chacha20(&uuid);

    // Buffers for reading and writing
    let mut relay_buf = [0u8; 1024];
    let mut target_buf = [0u8; 1024];
    loop {
        select! {
            // Read from the incoming socket (relay),
            // decrypt it, and send it to the target socket
            result1 = relay_socket.read(&mut relay_buf) => {
                let read_bytes = result1?;
                if read_bytes == 0 {
                    println!("Exiting...");
                    return Ok(());
                } else {
                    let data = apply_keystream_and_return_new(&mut relay_cipher_recv, &mut relay_buf[..read_bytes]);
                    target_socket.write_all(&data).await?;
                }
            }

            // If the target socket has something to say,
            // read it and forward it to the relay
            result2 = target_socket.read(&mut target_buf) => {
                let read_bytes = result2?;
                if read_bytes == 0 {
                    println!("Exiting...");
                    return Ok(());
                } else {
                    let encrypted_data = apply_keystream_and_return_new(&mut relay_cipher_send, &mut target_buf[..read_bytes]);
                    relay_socket.write_all(&encrypted_data).await?;
                }
            }
        }
    }
    Ok(())
}
