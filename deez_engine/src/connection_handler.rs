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
use std::error::Error;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};
use rand::Rng;
use reqwest::Client;

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

async fn find_available_port() -> Option<u16> {
    let mut rng = rand::thread_rng();
    (8000..=8020).collect::<Vec<u16>>()
        .into_iter()
        .filter(|port| {
            let addr = format!("0.0.0.0:{}", port);
            std::net::TcpListener::bind(addr).is_ok()
        })
        .collect::<Vec<u16>>()
        .into_iter()
        .nth(rng.gen_range(0, 20))
}

async fn find_random_free_port() -> u16 {
    let listener = TcpListener::bind("0.0.0.0:0").await.expect("Failed to bind to random port");
    listener.local_addr().unwrap().port()
}

async fn register_port(port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    // Replace with your actual service discovery endpoint
    let response = client.post("http://service-discovery/register")
        .json(&serde_json::json!({
            "service": "socks5-proxy",
            "port": port
        }))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err("Failed to register port with service discovery".into());
    }
    Ok(())
}

pub async fn spawn_connection() -> fast_socks5::Result<()> {
    let whitelisted_ips = Arc::new(init_whitelist());

    // Try binding to ports for 5 minutes
    let start_time = Instant::now();
    let max_duration = Duration::from_secs(300); // 5 minutes
    let mut bound_port = None;

    while start_time.elapsed() < max_duration {
        if let Some(port) = find_available_port().await {
            match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                Ok(listener) => {
                    bound_port = Some(port);
                    info!("Successfully bound to port {}", port);

                    // Register port with service discovery
                    match register_port(port).await {
                        Ok(_) => info!("Successfully registered port {} with service discovery", port),
                        Err(e) => error!("Failed to register port with service discovery: {:?}", e)
                    }

                    // Create SOCKS5 server configuration
                    let mut config: Config<Auth> = Config::default();
                    config.set_request_timeout(1);
                    config.set_skip_auth(false);
                    let config = config.with_authentication(Auth {
                        username: "deez".to_string(),
                        password_hash: "e81aead8ea4b7c2bd58be7ac2b6579833e579d00df5676dd8c9c010d23625423".to_string(),
                    });

                    // Spawn SOCKS5 server (using port + 1 for SOCKS5 server)
                    let socks_port = port + 10000;
                    let socks_config = config.clone();
                    tokio::spawn(async move {
                        match <Socks5Server>::bind(format!("127.0.0.1:{}", socks_port)).await {
                            Ok(socks_server) => {
                                let socks_server = socks_server.with_config(socks_config);
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
                        match listener.accept().await {
                            Ok((mut incoming_stream, addr)) => {
                                // Check IP whitelist
                                if !is_ip_whitelisted(&addr.ip(), &whitelisted_ips) {
                                    info!("Rejected connection from non-whitelisted IP: {}", addr.ip());
                                    continue;
                                }

                                info!("Accepted connection from whitelisted IP: {}", addr.ip());

                                // Forward whitelisted connection to SOCKS5 server
                                match TcpStream::connect(format!("127.0.0.1:{}", socks_port)).await {
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
                Err(_) => {
                    info!("Port {} unavailable, retrying in 1 second", port);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }
        }
    }

    // If we couldn't bind to any port in range after 5 minutes, use a random free port
    if bound_port.is_none() {
        let port = find_random_free_port().await;
        info!("Using random free port {} after exhausting retry attempts", port);

        // Register the random port with service discovery
        match register_port(port).await {
            Ok(_) => info!("Successfully registered random port {} with service discovery", port),
            Err(e) => error!("Failed to register random port with service discovery: {:?}", e)
        }

        bound_port = Some(port);
    }

    Ok(())
}