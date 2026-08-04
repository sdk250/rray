use tokio::{
    net::TcpStream,
    time::{ timeout, Duration }
};

use crate::error::Result;

const SERVER_HOST: &'static str = "192.168.3.2";
const SERVER_PORT: u16 = 20881;

pub(crate) async fn handle_connection() -> Result<()> {
    let mut server_socket = timeout(
        Duration::from_secs(5),
        TcpStream::connect((SERVER_HOST, SERVER_PORT))
    ).await??;

    // Set TCP_NODELAY to disable Nagle's algorithm for low-latency communication
    server_socket.set_nodelay(true)?;

    Ok(())
}
