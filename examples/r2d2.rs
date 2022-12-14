fn main() {
    let pool = r2d2::Pool::new(orcinus::r2d2::MysqlTcpConnection {
        addr: "127.0.0.1:3306",
        con_info: orcinus::ConnectInfo::new("root", "root").database("test"),
    })
    .expect("Failed to connect with r2d2");

    let mut client = pool.get().expect("Failed to get connection from pool");
    {
        let mut row_iter = client
            .fetch_all("Select * from test_data")
            .expect("Failed to send query command");

        for r in &mut row_iter {
            println!(
                "row: {:?}",
                r.expect("Failed to read resultset")
                    .decompose_values()
                    .collect::<Vec<_>>()
            );
        }

        println!("enumeration end: more_result={:?}", row_iter.has_more_resultset());
    }

    let stmt = client
        .prepare("Select * from test_data where id=?")
        .expect("Failed to prepare stmt");

    {
        let mut resultset_iter = client
            .fetch_all_statement(&stmt, &[(orcinus::protos::Value::Long(7), false)], true)
            .expect("Faield to execute stmt");
        let column_types = unsafe { resultset_iter.column_types_unchecked().collect::<Vec<_>>() };

        for r in &mut resultset_iter {
            let r = r.expect("Failed to read resultset");
            let values = r
                .decode_values(&column_types)
                .collect::<Result<Vec<_>, _>>()
                .expect("Failed to decode row value");
            println!("row: {values:?}");
        }

        println!(
            "resultset finished: more_result={:?}",
            resultset_iter.has_more_resultset()
        );
    }

    client.close_statement(stmt).expect("Failed to close statement");
}
