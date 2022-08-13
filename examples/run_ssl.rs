use futures_util::TryStreamExt;
use orcinus::{authentication::Authentication, protos::ClientPacket};
use tokio::io::AsyncWriteExt;

/// do not use this at other of localhost connection
pub struct MysqlCertForceVerifier {
    mysql_pubkey_der: std::sync::Arc<parking_lot::RwLock<Vec<u8>>>,
}
impl rustls::client::ServerCertVerifier for MysqlCertForceVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let cert = x509_parser::parse_x509_certificate(&end_entity.0[..])
            .expect("invalid certificate format");
        println!("end entity subject: {}", cert.1.subject);
        *self.mysql_pubkey_der.write() = cert.1.public_key().raw.to_owned();

        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[tokio::main]
async fn main() {
    let stream = tokio::net::TcpStream::connect("127.0.0.1:3306")
        .await
        .expect("Failed to connect");
    let mut stream = tokio::io::BufStream::new(stream);
    let (mut sequence_id, server_handshake) = orcinus::protos::Handshake::read_packet(&mut stream)
        .await
        .expect("Failed to read initial handshake");
    println!("sequence id: {sequence_id}");
    println!("server_handshake: {server_handshake:?}");

    let server_caps = match server_handshake {
        orcinus::protos::Handshake::V10Long(ref p) => p.short.capability_flags,
        orcinus::protos::Handshake::V10Short(ref p) => p.capability_flags,
        _ => orcinus::protos::CapabilityFlags::new(),
    };
    let mut required_caps = orcinus::protos::CapabilityFlags::new();
    required_caps
        .set_support_41_protocol()
        .set_support_secure_connection()
        .set_use_long_password()
        .set_support_deprecate_eof()
        .set_connect_with_db()
        .set_client_plugin_auth()
        .set_support_plugin_auth_lenenc_client_data()
        .set_support_ssl();
    let capability = required_caps & server_caps;

    sequence_id += 1;
    orcinus::protos::SSLRequest {
        capability: required_caps & server_caps,
        max_packet_size: 16777216,
        character_set: 0xff,
    }
    .write_packet(&mut stream, sequence_id)
    .await
    .expect("Failed to send ssl request");
    stream.flush().await.expect("Failed to flush stream");

    let mysql_pubkey = std::sync::Arc::new(parking_lot::RwLock::new(Vec::new()));
    let mut cc = tokio_rustls::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(std::sync::Arc::new(MysqlCertForceVerifier {
            mysql_pubkey_der: mysql_pubkey.clone(),
        }))
        .with_no_client_auth();
    cc.enable_sni = false;
    let stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cc))
        .connect(
            tokio_rustls::rustls::ServerName::try_from("localhost").expect("invalid dns name?"),
            stream.into_inner(),
        )
        .await
        .expect("Failed to connect tls");
    let mut stream = tokio::io::BufStream::new(stream);
    let mysql_spki = std::mem::replace(&mut *mysql_pubkey.write(), Vec::new());

    let con_info = orcinus::authentication::ConnectionInfo {
        client_capabilities: capability,
        max_packet_size: 16777216,
        character_set: 0xff,
        username: "root",
        password: "root",
        database: Some("sandstar"),
    };

    let (auth_plugin_name, auth_data_1, auth_data_2) = match server_handshake {
        orcinus::protos::Handshake::V10Long(ref p) => (
            p.auth_plugin_name.as_deref(),
            &p.short.auth_plugin_data_part_1[..],
            p.auth_plugin_data_part_2.as_deref(),
        ),
        orcinus::protos::Handshake::V10Short(ref p) => (None, &p.auth_plugin_data_part_1[..], None),
        orcinus::protos::Handshake::V9(ref p) => (None, p.scramble.as_bytes(), None),
    };
    let (resp, _) = match auth_plugin_name {
        Some(x) if x == orcinus::authentication::Native41::NAME => {
            orcinus::authentication::Native41 {
                server_data_1: auth_data_1,
                server_data_2: auth_data_2.expect("no extra data passed from server"),
            }
            .run(&mut stream, &con_info, sequence_id + 1)
            .await
            .expect("Failed to authenticate")
        }
        Some(x) if x == orcinus::authentication::ClearText::NAME => {
            orcinus::authentication::ClearText
                .run(&mut stream, &con_info, sequence_id + 1)
                .await
                .expect("Failed to authenticate")
        }
        Some(x) if x == orcinus::authentication::SHA256::NAME => orcinus::authentication::SHA256 {
            server_spki_der: Some(&mysql_spki),
            scramble_buffer_1: auth_data_1,
            scramble_buffer_2: auth_data_2.unwrap_or(&[]),
        }
        .run(&mut stream, &con_info, sequence_id + 1)
        .await
        .expect("Failed to authenticate"),
        Some(x) if x == orcinus::authentication::CachedSHA256::NAME => {
            orcinus::authentication::CachedSHA256(orcinus::authentication::SHA256 {
                server_spki_der: Some(&mysql_spki),
                scramble_buffer_1: auth_data_1,
                scramble_buffer_2: auth_data_2.unwrap_or(&[]),
            })
            .run(&mut stream, &con_info, sequence_id + 1)
            .await
            .expect("Failed to authenticate")
        }
        Some(x) => unreachable!("unknown auth plugin: {x}"),
        None => unreachable!("auth plugin is not specified"),
    };
    println!("connection: {resp:?}");

    let mut client = orcinus::Client::new(stream, capability);
    {
        let mut row_stream = client
            .fetch_all("Select * from friends")
            .await
            .expect("Failed to send query command");

        while let Some(r) = row_stream
            .try_next()
            .await
            .expect("Failed to read resultset")
        {
            println!("row: {:?}", r.decompose_values().collect::<Vec<_>>());
        }

        println!(
            "enumeration end: more_result={:?}",
            row_stream.has_more_resultset()
        );
    }

    let client = client.share();
    let mut stmt = client
        .prepare("Select * from friends where id=?")
        .await
        .expect("Failed to prepare stmt");
    let exec_resp = stmt
        .execute(&[(orcinus::protos::Value::Long(7), false)], true)
        .await
        .expect("Faield to execute stmt");

    {
        let mut c = client.lock();

        let column_count = match exec_resp {
            orcinus::protos::StmtExecuteResult::Resultset { column_count } => column_count,
            _ => unreachable!("unexpected select statement result"),
        };
        let mut resultset_stream = c
            .binary_resultset_stream(column_count as _)
            .await
            .expect("Failed to load resultset heading columns");
        let column_types = unsafe {
            resultset_stream
                .column_types_unchecked()
                .collect::<Vec<_>>()
        };

        while let Some(r) = resultset_stream
            .try_next()
            .await
            .expect("Failed to read resultset")
        {
            let values = r
                .decode_values(&column_types)
                .collect::<Result<Vec<_>, _>>()
                .expect("Failed to decode row value");
            println!("row: {values:?}");
        }

        println!(
            "resultset finished: more_result={:?}",
            resultset_stream.has_more_resultset()
        );
    }

    stmt.close().await.expect("Failed to close stmt");
    client
        .unshare()
        .quit()
        .await
        .expect("Failed to quit client");
}
