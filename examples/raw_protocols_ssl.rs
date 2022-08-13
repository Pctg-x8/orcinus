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
    if !server_caps.support_ssl() {
        panic!("server does not support ssl");
    }

    let mut required_caps = orcinus::protos::CapabilityFlags::new();
    required_caps
        .set_support_41_protocol()
        .set_support_secure_connection()
        .set_use_long_password()
        .set_support_deprecate_eof()
        .set_support_ssl()
        .set_connect_with_db()
        .set_client_plugin_auth()
        .support_plugin_auth_lenenc_client_data();

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

    let client_capability = required_caps & server_caps;
    let additional_authentication_method;
    match server_handshake {
        orcinus::protos::Handshake::V10Long(ref p) => {
            let auth_response = match p.auth_plugin_name {
                Some(ref x) if x == orcinus::authentication::Native41::NAME => {
                    additional_authentication_method = None;
                    orcinus::authentication::Native41 {
                        server_data_1: &p.short.auth_plugin_data_part_1,
                        server_data_2: p
                            .auth_plugin_data_part_2
                            .as_deref()
                            .expect("no extra data passed from server"),
                    }
                    .generate("")
                }
                Some(ref x) if x == orcinus::authentication::ClearText::NAME => {
                    additional_authentication_method = None;
                    orcinus::authentication::ClearText.generate("")
                }
                Some(ref x) if x == orcinus::authentication::SHA256::NAME => {
                    let a = orcinus::authentication::SHA256 {
                        server_spki_der: Some(&mysql_spki),
                        scramble_buffer_1: &p.short.auth_plugin_data_part_1,
                        scramble_buffer_2: p.auth_plugin_data_part_2.as_deref().unwrap_or(&[]),
                    };
                    let bytes = a.generate("root");
                    additional_authentication_method = None;
                    bytes
                }
                Some(ref x) if x == orcinus::authentication::CachedSHA256::NAME => {
                    let a =
                        orcinus::authentication::CachedSHA256(orcinus::authentication::SHA256 {
                            server_spki_der: None,
                            scramble_buffer_1: &p.short.auth_plugin_data_part_1,
                            scramble_buffer_2: p.auth_plugin_data_part_2.as_deref().unwrap_or(&[]),
                        });
                    let bytes = a.generate("root");
                    additional_authentication_method = Some((
                        x,
                        &p.short.auth_plugin_data_part_1,
                        p.auth_plugin_data_part_2.as_deref().unwrap_or(&[]),
                    ));
                    bytes
                }
                Some(ref x) => unreachable!("unknown auth plugin: {x}"),
                None => unreachable!("auth plugin is not specified"),
            };
            println!("auth: {auth_response:?}");

            sequence_id += 1;
            if client_capability.support_41_protocol() {
                let resp = orcinus::protos::HandshakeResponse41 {
                    capability: client_capability,
                    max_packet_size: 16777216,
                    character_set: 0xff,
                    username: "root",
                    auth_response: if client_capability.support_plugin_auth_lenenc_client_data() {
                        orcinus::protos::HandshakeResponse41AuthResponse::PluginAuthLenEnc(
                            &auth_response,
                        )
                    } else if client_capability.support_secure_connection() {
                        orcinus::protos::HandshakeResponse41AuthResponse::SecureConnection(
                            &auth_response,
                        )
                    } else {
                        orcinus::protos::HandshakeResponse41AuthResponse::Plain(&auth_response)
                    },
                    database: Some("sandstar"),
                    auth_plugin_name: p.auth_plugin_name.as_deref(),
                    connect_attrs: Default::default(),
                };

                resp.write_packet(&mut stream, sequence_id)
                    .await
                    .expect("Failed to send 41 handshake response");
            } else {
                let resp = orcinus::protos::HandshakeResponse320 {
                    capability: p.short.capability_flags & required_caps,
                    max_packet_size: 10,
                    username: "root",
                    auth_response: &auth_response,
                    database: Some("sandstar"),
                };

                resp.write_packet(&mut stream, sequence_id)
                    .await
                    .expect("Failed to send old handshake response")
            }
        }
        _ => unreachable!("this handshake request cannot be processed"),
    }
    stream.flush().await.expect("Failed to flush buffer");
    if let Some((name, s1, s2)) = additional_authentication_method {
        let orcinus::protos::AuthMoreData(cont) =
            orcinus::protos::AuthMoreDataResponse::read_packet(&mut stream, client_capability)
                .await
                .expect("Failed to read more auth data packet")
                .into_result()
                .expect("Failed to requrest more auth data");
        if cont != vec![0x03] {
            // fast auth failed
            assert_eq!(cont, vec![0x04]); // perform_full_authentication

            let auth_response = if name == orcinus::authentication::SHA256::NAME {
                orcinus::authentication::SHA256 {
                    server_spki_der: Some(&mysql_spki),
                    scramble_buffer_1: s1,
                    scramble_buffer_2: s2,
                }
                .generate("root")
            } else if name == orcinus::authentication::CachedSHA256::NAME {
                orcinus::authentication::CachedSHA256(orcinus::authentication::SHA256 {
                    server_spki_der: Some(&mysql_spki),
                    scramble_buffer_1: s1,
                    scramble_buffer_2: s2,
                })
                .generate("root")
            } else {
                unreachable!("unknown authentication method for continue")
            };

            orcinus::protos::write_packet(&mut stream, &auth_response, sequence_id + 2)
                .await
                .expect("Failed to write full response");
            stream.flush().await.expect("Failed to flush");
        }
    }

    let resp = orcinus::protos::HandshakeResult::read_packet(&mut stream, client_capability)
        .await
        .expect("Failed to read handshake result")
        .into_result()
        .expect("Failed to handshake");
    println!("connection: {resp:?}");

    orcinus::protos::QueryCommand("Select * from friends")
        .write_packet(&mut stream, 0)
        .await
        .expect("Failed to send query command");
    stream.flush().await.expect("Failed to flush buffer");
    let qc_result =
        orcinus::protos::QueryCommandResponse::read_packet(&mut stream, client_capability)
            .await
            .expect("Failed to read query command result");
    println!("result: {qc_result:?}");
    let field_count = match qc_result {
        orcinus::protos::QueryCommandResponse::Resultset { column_count } => column_count,
        _ => unreachable!("unexpected command response"),
    };
    let mut columns = Vec::with_capacity(field_count as _);
    for _ in 0..field_count {
        columns.push(
            orcinus::protos::ColumnDefinition41::read_packet(&mut stream)
                .await
                .expect("Failed to read column def"),
        );
    }
    if !client_capability.support_deprecate_eof() {
        orcinus::protos::EOFPacket41::expected_read_packet(&mut stream)
            .await
            .expect("Failed to read eof packet of columns");
    }
    println!("columns: {columns:#?}");

    loop {
        let rc = orcinus::protos::Resultset41::read_packet(&mut stream, client_capability)
            .await
            .expect("Failed to read resultset entry");

        match rc {
            orcinus::protos::Resultset41::Row(r) => {
                println!("row: {:?}", r.decompose_values().collect::<Vec<_>>());
            }
            orcinus::protos::Resultset41::Err(e) => {
                println!("errored {}", e.error_message);
                break;
            }
            orcinus::protos::Resultset41::Ok(o) => {
                println!(
                    "ok more_results={}",
                    o.status_flags().unwrap_or_default().more_result_exists()
                );
                break;
            }
            orcinus::protos::Resultset41::EOF(e) => {
                println!("eof more_results={}", e.status_flags.more_result_exists());
                break;
            }
        }
    }

    orcinus::protos::StmtPrepareCommand("Select * from friends where id=?")
        .write_packet(&mut stream, 0)
        .await
        .expect("Failed to write prepare command");
    stream.flush().await.expect("Failed to flush stream");
    let resp = orcinus::protos::StmtPrepareResult::read_packet(&mut stream, client_capability)
        .await
        .expect("Failed to read prepare result packet")
        .into_result()
        .expect("Failed to prepare stmt");
    println!("stmt prepare: {resp:?}");
    let mut params = Vec::with_capacity(resp.num_params as _);
    for _ in 0..resp.num_params {
        params.push(
            orcinus::protos::ColumnDefinition41::read_packet(&mut stream)
                .await
                .expect("Failed to read params packet"),
        );
    }
    if !client_capability.support_deprecate_eof() {
        orcinus::protos::EOFPacket41::expected_read_packet(&mut stream)
            .await
            .expect("Failed to read EOF packet");
    }
    let mut columns = Vec::with_capacity(resp.num_columns as _);
    for _ in 0..resp.num_columns {
        columns.push(
            orcinus::protos::ColumnDefinition41::read_packet(&mut stream)
                .await
                .expect("Failed to read params packet"),
        );
    }
    if !client_capability.support_deprecate_eof() {
        orcinus::protos::EOFPacket41::expected_read_packet(&mut stream)
            .await
            .expect("Failed to read EOF packet");
    }
    println!("params: {params:#?}");
    println!("columns: {columns:#?}");

    let parameters = [(orcinus::protos::Value::Long(7), false)];
    orcinus::protos::StmtExecuteCommand {
        statement_id: resp.statement_id,
        flags: orcinus::protos::StmtExecuteFlags::new(),
        parameters: &parameters,
        requires_rebound_parameters: true,
    }
    .write_packet(&mut stream, 0)
    .await
    .expect("Failed to write execute packet");
    stream.flush().await.expect("Failed to flush stream");
    let exec_resp = orcinus::protos::StmtExecuteResult::read_packet(&mut stream, client_capability)
        .await
        .expect("Failed to read stmt execute result");
    let column_count = match exec_resp {
        orcinus::protos::StmtExecuteResult::Resultset { column_count } => column_count,
        _ => unreachable!("unexpected select statement result"),
    };

    {
        let mut resultset_stream =
            orcinus::BinaryResultsetStream::new(&mut stream, client_capability, column_count as _)
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

    orcinus::protos::StmtCloseCommand(resp.statement_id)
        .write_packet(&mut stream, 0)
        .await
        .expect("Failed to write stmt close command");

    orcinus::protos::QuitCommand
        .write_packet(&mut stream, 0)
        .await
        .expect("Failed to send quit command");
    stream.flush().await.expect("Failed to flush buffer");
    stream
        .into_inner()
        .shutdown()
        .await
        .expect("Failed to shutdown the connection");
}
