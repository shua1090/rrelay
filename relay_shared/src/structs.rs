/*  This file contains
    shared structs that both
    the client and server will use
*/

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
        /* Connection ID */ String,
        /* Connection Details */ Connection,
    ),
    // Remove connection is
    // when the connection is closed
    // on the exposed server, so
    // the corresponding ports
    // must be closed on the hidden side
    RemoveConnection(
        /* port */ u16,
        /* Connection ID */ String,
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
