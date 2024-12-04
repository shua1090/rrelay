/*  This file contains
    shared structs that both
    the client and server will use
*/

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum RelayConfig {
    // This message type
    // contains a public key
    KeyExchange(Vec<u8>),
    // New Connection is
    // when relay gets a new
    // connection, so it will
    // open up a port, ask the
    // hidden server to do all
    // its necessary config,
    // and then connect to the port
    NewConnection(
        /* port */ u16,
        /* Connection ID */ [u8; 32],
        /* Connection Details */ Connection,
    ),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Connection {
    // Port that is attached to the exposed relay server
    pub incoming_port: u16,
    // Incoming Address
    pub incoming_addr: String,
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct RelayCmdOptions {
    // Relay Config Port
    #[arg(
        short,
        long,
        default_value = "10000",
        help = "Configuration port to expose that allows the hidden server to be configured"
    )]
    pub config_port: u16,

    // Exposed Server Port
    #[arg(
        short,
        long,
        default_value = "20000",
        help = "Port to accept connections from (these connections are the ones that are relayed)"
    )]
    pub exposed_port: u16,
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct HiddenCmdOptions {
    #[arg(
        short,
        long,
        default_value = "127.0.0.1",
        help = "IP Address of the exposed relay server"
    )]
    pub relay_ip: String,

    // Relay Config Port
    #[arg(
        short,
        long,
        default_value = "10000",
        help = "Config port of the exposed relay server"
    )]
    pub config_port: u16,

    // Target connection Port
    // (i.e. exposed port)
    #[arg(
        short,
        long,
        default_value = "20000",
        help = "Port to relay the data to"
    )]
    pub target_port: u16,
}
