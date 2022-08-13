use futures_util::TryStreamExt;

#[tokio::main]
async fn main() {
    let stream = tokio::net::TcpStream::connect("127.0.0.1:3306")
        .await
        .expect("Failed to connect");
    let stream = tokio::io::BufStream::new(stream);

    let connect_info = orcinus::ConnectInfo::new("root", "root").database("test");
    let mut client = orcinus::Client::handshake(stream, &connect_info)
        .await
        .expect("Failed to connect to db server");

    {
        let mut row_stream = client
            .fetch_all("Select * from test_data")
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
        .prepare("Select * from test_data where id=?")
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
