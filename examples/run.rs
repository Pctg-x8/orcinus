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
                .set_use_long_password();

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
                    database: None,
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
                    database: None,
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

    let resp = orcinus::protos::GenericResultPacket::read_packet(&mut stream, client_capability)
        .await
        .expect("Failed to read handshake response");
    println!("{resp:?}");

    sequence_id += 1;
    orcinus::protos::QuitCommand
        .write_packet(&mut stream, sequence_id)
        .await
        .expect("Failed to send quit command");
    stream.flush().await.expect("Failed to flush buffer");
    stream
        .into_inner()
        .shutdown()
        .await
        .expect("Failed to shutdown the connection");
}
