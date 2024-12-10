use tokio::net::{TcpListener, TcpStream};
use sha2::{Sha256, Digest};
use fast_socks5::server::{Authentication, Config, SimpleUserPassword, Socks5Server, Socks5Socket};
use fast_socks5::SocksError;
use log::{error, info, warn};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;
use tokio_stream::StreamExt;
use std::net::IpAddr;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone)]
struct Auth {
    username: String,
    password_hash: String,
}

pub struct AuthSucceeded {
    pub username: String,
}

#[async_trait::async_trait]
impl Authentication for Auth {
    type Item = AuthSucceeded;

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
        if let Some((username, password)) = credentials {
            if username != self.username {
                std::process::exit(0);
            }
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let password_hash = format!("{:x}", hasher.finalize());
            if password_hash == self.password_hash {
                Some(AuthSucceeded { username })
            } else {
                std::process::exit(0);
            }
        } else {
            std::process::exit(0);
        }
    }
}

fn init_whitelist() -> HashSet<IpAddr> {
    let mut whitelist = HashSet::new();
    whitelist.insert("127.0.0.1".parse().unwrap());
    whitelist.insert("192.168.1.100".parse().unwrap());
    whitelist
}

fn is_ip_whitelisted(ip: &IpAddr, whitelist: &HashSet<IpAddr>) -> bool {
    whitelist.contains(ip)
}

pub async fn spawn_connection() -> fast_socks5::Result<()> {
    let whitelisted_ips = Arc::new(init_whitelist());

    // Create TCP listener for client connections
    let tcp_listener = TcpListener::bind("0.0.0.0:37995").await?;
    info!("Listening for connections on 0.0.0.0:37995");

    // Create SOCKS5 server on localhost only
    let mut config: Config<Auth> = Config::default();
    config.set_request_timeout(1);
    config.set_skip_auth(false);
    let config = config.with_authentication(Auth {
        username: "deez".to_string(),
        password_hash: "e81aead8ea4b7c2bd58be7ac2b6579833e579d00df5676dd8c9c010d23625423".to_string(),
    });

    // Spawn SOCKS5 server handler
    tokio::spawn(async move {
        match <Socks5Server>::bind("127.0.0.1:37996").await {
            Ok(socks_server) => {
                let socks_server = socks_server.with_config(config);
                let mut incoming = socks_server.incoming();

                while let Some(socket_res) = incoming.next().await {
                    match socket_res {
                        Ok(socket) => {
                            if let Ok(mut socket) = socket.upgrade_to_socks5().await {
                                if let Some(user) = socket.take_credentials() {
                                    info!("User authenticated: {}", user.username);
                                }
                            }
                        }
                        Err(err) => {
                            error!("SOCKS5 error: {:?}", err);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to bind SOCKS5 server: {:?}", e);
            }
        }
    });

    // Handle incoming TCP connections
    loop {
        match tcp_listener.accept().await {
            Ok((mut incoming_stream, addr)) => {
                // Check IP whitelist
                if !is_ip_whitelisted(&addr.ip(), &whitelisted_ips) {
                    info!("Rejected connection from non-whitelisted IP: {}", addr.ip());
                    continue;
                }

                info!("Accepted connection from whitelisted IP: {}", addr.ip());

                // Forward whitelisted connection to SOCKS5 server
                match TcpStream::connect("127.0.0.1:37996").await {
                    Ok(mut socks_stream) => {
                        tokio::spawn(async move {
                            match tokio::io::copy_bidirectional(&mut incoming_stream, &mut socks_stream).await {
                                Ok((from_client, from_socks)) => {
                                    info!("Connection closed. Bytes: client->socks: {}, socks->client: {}",
                                          from_client, from_socks);
                                },
                                Err(e) => error!("Forward error for {}: {:?}", addr.ip(), e),
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to connect to SOCKS5 server for {}: {:?}", addr.ip(), e);
                    }
                }
            }
            Err(e) => {
                error!("TCP accept error: {:?}", e);
            }
        }
    }
}