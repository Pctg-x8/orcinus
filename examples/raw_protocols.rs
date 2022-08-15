use futures_util::TryStreamExt;
use orcinus::{authentication::Authentication, protos::ClientPacket};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() {
    let stream = tokio::net::TcpStream::connect("127.0.0.1:3306")
        .await
        .expect("Failed to connect");
    let mut stream = tokio::io::BufStream::new(stream);
    let (server_handshake, sequence_id) = orcinus::protos::Handshake::read_packet(&mut stream)
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
    let (resp, _) = match auth_plugin_name {
        Some(x) if x == orcinus::authentication::Native41::NAME => {
            let auth_response = orcinus::authentication::gen_secure_password_auth_response(
                "",
                auth_data_1,
                auth_data_2.expect("no extra data passed from server"),
            );

            if capability.support_41_protocol() {
                orcinus::protos::HandshakeResponse41 {
                    capability,
                    max_packet_size: 16777216,
                    character_set: 0xff,
                    username: "root",
                    auth_response: &auth_response,
                    database: Some("test"),
                    auth_plugin_name,
                    connect_attrs: Default::default(),
                }
                .write_packet(&mut stream, sequence_id + 1)
                .await
                .expect("Failed to send handshake response");
            } else {
                orcinus::protos::HandshakeResponse320 {
                    capability,
                    max_packet_size: 16777216,
                    username: "root",
                    auth_response: &auth_response,
                    database: Some("test"),
                }
                .write_packet(&mut stream, sequence_id + 1)
                .await
                .expect("Failed to send handshake response");
            }
            stream.flush().await.expect("Failed to flush stream");

            orcinus::protos::GenericOKErrPacket::read_packet(&mut stream, capability)
                .await
                .expect("Failed to read handshake result")
                .into_result()
                .expect("Failed to handshake")
        }
        Some(x) if x == orcinus::authentication::ClearText::NAME => {
            if capability.support_41_protocol() {
                orcinus::protos::HandshakeResponse41 {
                    capability,
                    max_packet_size: 16777216,
                    character_set: 0xff,
                    username: "root",
                    auth_response: b"root",
                    database: Some("test"),
                    auth_plugin_name,
                    connect_attrs: Default::default(),
                }
                .write_packet(&mut stream, sequence_id + 1)
                .await
                .expect("Failed to send handshake response");
            } else {
                orcinus::protos::HandshakeResponse320 {
                    capability,
                    max_packet_size: 16777216,
                    username: "root",
                    auth_response: b"root",
                    database: Some("test"),
                }
                .write_packet(&mut stream, sequence_id + 1)
                .await
                .expect("Failed to send handshake response");
            }
            stream.flush().await.expect("Failed to flush stream");

            orcinus::protos::GenericOKErrPacket::read_packet(&mut stream, capability)
                .await
                .expect("Failed to read handshake result")
                .into_result()
                .expect("Failed to handshake")
        }
        Some(x) if x == orcinus::authentication::CachedSHA256::NAME => {
            let d2 = auth_data_2.unwrap_or(&[]);
            let auth_response = orcinus::authentication::caching_sha2_gen_fast_auth_response(
                "root",
                auth_data_1,
                &d2[..d2.len() - 1], // requires removing last byte
            );

            if capability.support_41_protocol() {
                orcinus::protos::HandshakeResponse41 {
                    capability,
                    max_packet_size: 16777216,
                    character_set: 0xff,
                    username: "root",
                    auth_response: &auth_response,
                    database: Some("test"),
                    auth_plugin_name,
                    connect_attrs: Default::default(),
                }
                .write_packet(&mut stream, sequence_id + 1)
                .await
                .expect("Failed to send handshake response");
            } else {
                orcinus::protos::HandshakeResponse320 {
                    capability,
                    max_packet_size: 16777216,
                    username: "root",
                    auth_response: &auth_response,
                    database: Some("test"),
                }
                .write_packet(&mut stream, sequence_id + 1)
                .await
                .expect("Failed to send handshake response");
            }
            stream.flush().await.expect("Failed to flush stream");

            let (orcinus::protos::AuthMoreData(d), _) =
                orcinus::protos::AuthMoreDataResponse::read_packet(&mut stream, capability)
                    .await
                    .expect("Failed to read more data response")
                    .into_result()
                    .expect("Failed to auth");
            assert_eq!(d, [0x03]); // 0x03 = fast auth ok

            orcinus::protos::GenericOKErrPacket::read_packet(&mut stream, capability)
                .await
                .expect("Failed to read handshake result")
                .into_result()
                .expect("Failed to handshake")
        }
        Some(x) => unreachable!("unknown auth plugin: {x}"),
        None => unreachable!("auth plugin is not specified"),
    };
    println!("connection: {resp:?}");

    orcinus::protos::QueryCommand("Select * from test_data")
        .write_packet(&mut stream, 0)
        .await
        .expect("Failed to send query command");
    stream.flush().await.expect("Failed to flush buffer");
    let qc_result = orcinus::protos::QueryCommandResponse::read_packet(&mut stream, capability)
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
    if !capability.support_deprecate_eof() {
        orcinus::protos::EOFPacket41::expected_read_packet(&mut stream)
            .await
            .expect("Failed to read eof packet of columns");
    }
    println!("columns: {columns:#?}");

    loop {
        let rc = orcinus::protos::Resultset41::read_packet(&mut stream, capability)
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

    orcinus::protos::StmtPrepareCommand("Select * from test_data where id=?")
        .write_packet(&mut stream, 0)
        .await
        .expect("Failed to write prepare command");
    stream.flush().await.expect("Failed to flush stream");
    let resp = orcinus::protos::StmtPrepareResult::read_packet(&mut stream, capability)
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
    if !capability.support_deprecate_eof() {
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
    if !capability.support_deprecate_eof() {
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
    let exec_resp = orcinus::protos::StmtExecuteResult::read_packet(&mut stream, capability)
        .await
        .expect("Failed to read stmt execute result");
    let column_count = match exec_resp {
        orcinus::protos::StmtExecuteResult::Resultset { column_count } => column_count,
        _ => unreachable!("unexpected select statement result"),
    };

    {
        let mut resultset_stream =
            orcinus::BinaryResultsetStream::new(&mut stream, capability, column_count as _)
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
