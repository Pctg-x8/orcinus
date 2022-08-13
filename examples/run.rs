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
        .set_support_plugin_auth_lenenc_client_data();
    let capability = required_caps & server_caps;

    let (auth_plugin_name, auth_data_1, auth_data_2) = match server_handshake {
        orcinus::protos::Handshake::V10Long(ref p) => (
            p.auth_plugin_name.as_deref(),
            &p.short.auth_plugin_data_part_1[..],
            p.auth_plugin_data_part_2.as_deref(),
        ),
        orcinus::protos::Handshake::V10Short(ref p) => (None, &p.auth_plugin_data_part_1[..], None),
        orcinus::protos::Handshake::V9(ref p) => (None, p.scramble.as_bytes(), None),
    };
    let auth_response = match auth_plugin_name {
        Some(x) if x == orcinus::authentication::Native41::NAME => {
            orcinus::authentication::Native41 {
                server_data_1: auth_data_1,
                server_data_2: auth_data_2.expect("no extra data passed from server"),
            }
            .generate("")
        }
        Some(x) if x == orcinus::authentication::ClearText::NAME => {
            orcinus::authentication::ClearText.generate("")
        }
        Some(x) if x == orcinus::authentication::SHA256::NAME => {
            let a = orcinus::authentication::SHA256 {
                server_spki_der: None,
                scramble_buffer_1: auth_data_1,
                scramble_buffer_2: auth_data_2.unwrap_or(&[]),
            };
            a.generate("root")
        }
        Some(x) if x == orcinus::authentication::CachedSHA256::NAME => {
            let a = orcinus::authentication::CachedSHA256(orcinus::authentication::SHA256 {
                server_spki_der: None,
                scramble_buffer_1: auth_data_1,
                scramble_buffer_2: auth_data_2.unwrap_or(&[]),
            });
            a.generate("root")
        }
        Some(x) => unreachable!("unknown auth plugin: {x}"),
        None => unreachable!("auth plugin is not specified"),
    };

    sequence_id += 1;
    if capability.support_41_protocol() {
        let resp = orcinus::protos::HandshakeResponse41 {
            capability,
            max_packet_size: 16777215,
            character_set: 0xff,
            username: "root",
            auth_response: if capability.support_plugin_auth_lenenc_client_data() {
                orcinus::protos::HandshakeResponse41AuthResponse::PluginAuthLenEnc(&auth_response)
            } else if capability.support_secure_connection() {
                orcinus::protos::HandshakeResponse41AuthResponse::SecureConnection(&auth_response)
            } else {
                orcinus::protos::HandshakeResponse41AuthResponse::Plain(&auth_response)
            },
            database: Some("sandstar"),
            auth_plugin_name,
            connect_attrs: Default::default(),
        };

        resp.write_packet(&mut stream, sequence_id)
            .await
            .expect("Failed to send 41 handshake response");
    } else {
        let resp = orcinus::protos::HandshakeResponse320 {
            capability,
            max_packet_size: 16777216,
            username: "root",
            auth_response: &auth_response,
            database: Some("sandstar"),
        };

        resp.write_packet(&mut stream, sequence_id)
            .await
            .expect("Failed to send old handshake response")
    }
    stream.flush().await.expect("Failed to flush buffer");

    let resp = orcinus::protos::HandshakeResult::read_packet(&mut stream, capability)
        .await
        .expect("Failed to read handshake result")
        .into_result()
        .expect("Failed to handshake");
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
