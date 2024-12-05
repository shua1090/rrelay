use clap::Parser;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::{select, spawn};

use relay_shared::crypto::*;
use relay_shared::structs::{Connection, RelayCmdOptions, RelayConfig};

#[tokio::main]
async fn main() -> io::Result<()> {
    let cmdline_options = RelayCmdOptions::parse();
    let config_port = cmdline_options.config_port;
    let exposed_port = cmdline_options.exposed_port;

    // Encryption basic setup
    let (our_secret_key, our_public_key) = generate_keypair();
    let mut chacha_key: Option<[u8; 32]> = None;

    println!("Starting config server on port: {}", config_port);
    println!("Once the target server connects to us (the relay), we will expose {} which forwards to the target", exposed_port);
    let _config_listener = TcpListener::bind(format!("0.0.0.0:{config_port}")).await?;
    let (mut config_socket, _) = _config_listener.accept().await?;
    println!(
        "Accepted connection from: {}. This is the hidden server, and who we're relaying messages to.",
        config_socket.peer_addr()?
    );

    // PREPARE ENCRYPTION
    // Via key exchange
    let mut buf = [0u8; 1024];
    let read_bytes = config_socket.read(&mut buf).await?;
    if read_bytes == 0 {
        println!("No bytes read from hidden server");
        println!("Exiting...");
        return Ok(());
    } else if let RelayConfig::KeyExchange(received_key_bytes) =
        bincode::deserialize::<RelayConfig>(&buf[..read_bytes]).unwrap()
    {
        // We now need to exchange keys
        let their_public_key = pubkey_from_bytes(received_key_bytes.as_slice());
        let shared_secret = generate_shared_secret(&their_public_key, &our_secret_key);

        // Send our public key to the hidden server
        let relay_config = RelayConfig::KeyExchange(pubkey_to_bytes(&our_public_key));
        config_socket
            .write_all(&bincode::serialize(&relay_config).unwrap())
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

    // Setup our symmetric encryption
    let mut chacha_instance = get_chacha20(&chacha_key.unwrap());

    let _data_listener = TcpListener::bind(format!("0.0.0.0:{exposed_port}")).await?;
    println!(
        "Exposed server started on port: {}. Forwarding messages now.",
        exposed_port
    );
    loop {
        // Get incoming connections
        let (incoming_socket, incoming_connection_details) = _data_listener.accept().await?;
        let connection_details = Connection {
            incoming_port: incoming_connection_details.port(),
            incoming_addr: incoming_connection_details.ip().to_string(),
        };

        // Tell the hidden server about the new connection
        // This is our relay port -> hidden
        let _relay_listener = TcpListener::bind("127.0.0.1:0").await?;
        let relay_port = _relay_listener.local_addr().unwrap().port();
        let uuid = generate_uuid();

        let relay_config = RelayConfig::NewConnection(relay_port, uuid, connection_details);

        // Write the relay config to the hidden server
        config_socket
            .write_all(
                apply_keystream_and_return_new(
                    &mut chacha_instance,
                    &mut bincode::serialize(&relay_config).unwrap(),
                )
                .as_slice(),
            )
            .await?;

        // Spawn a new task to handle the incoming connection
        spawn(handle_socket(
            incoming_socket,
            _relay_listener.accept().await?.0,
            uuid,
        ));
    }
}

/**
 * This function handles the connection between the relay and the hidden server.
 * It reads data from the incoming connection and relays it to the hidden server.
 * It also reads data from the hidden server and relays it to the incoming connection.
 */
async fn handle_socket(
    mut incoming_socket: TcpStream,
    mut relay_socket: TcpStream,
    uuid: [u8; 32],
) -> io::Result<()> {
    println!(
        "Starting connection: {}",
        uuid.iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>()
    );

    // We need two ciphers
    // since the internal state must be independent
    // for both sending and receiving
    // (if the order is messed up, the received/sent data might be messed up)
    let mut relay_cipher_send = get_chacha20(&uuid);
    let mut relay_cipher_recv = get_chacha20(&uuid);

    // Buffers for incoming and relayed data
    let mut incoming_buf = [0u8; 2048];
    let mut relay_buf = [0u8; 2048];

    loop {
        select! {
            // Relay from the target connection into
            // the relay
            result1 = incoming_socket.read(&mut incoming_buf) => {
                let read_bytes = result1?;
                if read_bytes == 0 {
                    println!("Exiting...");
                    return Ok(());
                } else {
                    // Encrypt and relay data to the hidden server
                    let data = apply_keystream_and_return_new(&mut relay_cipher_send, &mut incoming_buf[..read_bytes]);
                    relay_socket.write_all(&data).await?;
                }
            }
            // Read the relayed data and forward it to
            // the target connection
            result2 = relay_socket.read(&mut relay_buf) => {
                let read_bytes = result2?;
                if read_bytes == 0 {
                    println!("Exiting...");
                    return Ok(());
                } else {
                    // If we got data from the hidden server
                    // decrypt, and send it to the original incoming connections
                    let data = apply_keystream_and_return_new(&mut relay_cipher_recv, &mut relay_buf[..read_bytes]);
                    incoming_socket.write_all(&data).await?;
                }
            }
        }
    }
}
