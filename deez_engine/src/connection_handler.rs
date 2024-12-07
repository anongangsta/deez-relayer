use tokio::net::{TcpListener, TcpStream};
use sha2::{Sha256, Digest};
use std::error::Error;
use std::future::Future;
use fast_socks5::server::{Authentication, Config, SimpleUserPassword, Socks5Server, Socks5Socket};
use fast_socks5::SocksError;
use log::{error, info, warn};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;
use tokio_stream::StreamExt;

pub struct ConnectionHandler {
    username: String,
    password_hash: String,
    port: u16,
}

struct Auth {
    username: String,
    password_hash: String,
}

pub struct AuthSucceeded {
    pub username: String,
}

/// This is an example to auth via simple credentials.
/// If the auth succeed, we return the username authenticated with, for further uses.
#[async_trait::async_trait]
impl Authentication for Auth {
    type Item = AuthSucceeded;

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
        if let Some((username, password)) = credentials {
            // Client has supplied credentials
            if username != self.username {
                return None;
            }
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let password_hash = format!("{:x}", hasher.finalize());
            if password_hash == self.password_hash {
                // Some() will allow the authentication and the credentials
                // will be forwarded to the socket
                Some(AuthSucceeded { username })
            } else {
                // Credentials incorrect, we deny the auth
                None
            }
        } else {
            None
        }
    }
}

pub async fn spawn_socks_server() -> fast_socks5::Result<()> {
    let mut config:Config<Auth> = Config::default();
    config.set_request_timeout(10);
    config.set_skip_auth(false);
    let config = config.with_authentication(Auth { username: "deez".to_string(), password_hash: "e81aead8ea4b7c2bd58be7ac2b6579833e579d00df5676dd8c9c010d23625423".to_string() });

    let listener = <Socks5Server>::bind("0.0.0.0:37995").await?;
    let listener = listener.with_config(config);

    let mut incoming = listener.incoming();

    info!("Listen for socks connections @ {}", "0.0.0.0:37995");

    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {
                spawn_and_log_error(socket.upgrade_to_socks5());
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }

    Ok(())
}

fn spawn_and_log_error<F, T>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output =fast_socks5::Result<Socks5Socket<T, Auth>>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    task::spawn(async move {
        match fut.await {
            Ok(mut socket) => {
                if let Some(user) = socket.take_credentials() {
                    info!("user logged in with `{}`", user.username);
                }
            }
            Err(err) => error!("{:#}", &err),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};

    #[test]
    fn test_password_hash_generation() {
        let password = "C6FCpZ90s9rYC4dN";
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        println!("Password: {}", password);
        println!("Hash: {}", hash);

        // Verify the hash matches what we expect
        assert_eq!(
            hash,
            "7c5c7667d2f4cf2711e772912f668d5a83f4ad6468d08c17cd1bd0e4f5f971e0"
        );
    }
}