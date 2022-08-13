use futures_util::TryStreamExt;
use orcinus::{authentication::Authentication, protos::ClientPacket};
use tokio::io::AsyncWriteExt;

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
    let client_capability;
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
                        server_public_keyfile: None,
                        scramble_buffer_1: &p.short.auth_plugin_data_part_1,
                        scramble_buffer_2: p.auth_plugin_data_part_2.as_deref().unwrap_or(&[]),
                    };
                    let bytes = a.generate("root");
                    additional_authentication_method = Some((
                        x,
                        &p.short.auth_plugin_data_part_1,
                        p.auth_plugin_data_part_2.as_deref().unwrap_or(&[]),
                    ));
                    bytes
                }
                Some(ref x) if x == orcinus::authentication::CachedSHA256::NAME => {
                    let a =
                        orcinus::authentication::CachedSHA256(orcinus::authentication::SHA256 {
                            server_public_keyfile: None,
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
            let mut required_caps = orcinus::protos::CapabilityFlags::new();
            required_caps
                .set_support_41_protocol()
                .set_support_secure_connection()
                .set_use_long_password()
                .set_support_deprecate_eof();

            sequence_id += 1;
            if p.short.capability_flags.support_41_protocol() {
                let resp = orcinus::protos::HandshakeResponse41 {
                    capability: p.short.capability_flags & required_caps,
                    max_packet_size: 16777215,
                    character_set: p.character_set,
                    username: "root",
                    auth_response: if p
                        .short
                        .capability_flags
                        .support_plugin_auth_lenenc_client_data()
                    {
                        orcinus::protos::HandshakeResponse41AuthResponse::PluginAuthLenEnc(
                            &auth_response,
                        )
                    } else if p.short.capability_flags.support_secure_connection() {
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
                client_capability = resp.compute_final_capability_flags();

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
                client_capability = resp.compute_final_capability_flags();

                resp.write_packet(&mut stream, sequence_id)
                    .await
                    .expect("Failed to send old handshake response")
            }
        }
        _ => unreachable!("this handshake request cannot be processed"),
    }
    stream.flush().await.expect("Failed to flush buffer");
    if let Some((name, s1, s2)) = additional_authentication_method {
        let orcinus::protos::AuthMoreData(keyfile) =
            orcinus::protos::AuthMoreData::read_packet(&mut stream)
                .await
                .expect("Failed to read more data for auth");
        println!("keyfile: {keyfile:?}");
        let auth_response = if name == orcinus::authentication::SHA256::NAME {
            orcinus::authentication::SHA256 {
                server_public_keyfile: Some(&keyfile),
                scramble_buffer_1: s1,
                scramble_buffer_2: s2,
            }
            .generate("root")
        } else if name == orcinus::authentication::CachedSHA256::NAME {
            orcinus::authentication::CachedSHA256(orcinus::authentication::SHA256 {
                server_public_keyfile: Some(&keyfile),
                scramble_buffer_1: s1,
                scramble_buffer_2: s2,
            })
            .generate("root")
        } else {
            unreachable!("unknown authentication method for continue")
        };
        stream
            .write_all(&auth_response)
            .await
            .expect("Failed to send auth response");
    }

    let resp = orcinus::protos::HandshakeResult::read_packet(&mut stream, client_capability)
        .await
        .expect("Failed to read handshake result")
        .into_result()
        .expect("Failed to handshake");
    println!("connection: {resp:?}");

    let mut client = orcinus::Client::new(stream, client_capability);
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
