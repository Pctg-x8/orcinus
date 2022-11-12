use futures_util::TryStreamExt;

/// do not use this at other of localhost connection
pub struct MysqlCertForceVerifier;
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
        let cert = x509_parser::parse_x509_certificate(&end_entity.0[..]).expect("invalid certificate format");
        println!("end entity subject: {}", cert.1.subject);

        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[tokio::main]
async fn main() {
    let mut cc = tokio_rustls::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(std::sync::Arc::new(MysqlCertForceVerifier))
        .with_no_client_auth();
    cc.enable_sni = false;

    let pool = bb8::Pool::builder()
        .build(orcinus::bb8::MysqlConnection {
            addr: "127.0.0.1:3306",
            server_name: rustls::ServerName::try_from("localhost").expect("invalid host name"),
            con_info: orcinus::autossl_client::SSLConnectInfo {
                base: orcinus::ConnectInfo::new("root", "root").database("test"),
                ssl_config: std::sync::Arc::new(cc),
            },
        })
        .await
        .expect("Failed to connect with r2d2");

    let mut client = pool.get().await.expect("Failed to get connection from pool");
    {
        let mut row_stream = client
            .fetch_all("Select * from test_data")
            .await
            .expect("Failed to send query command");

        while let Some(r) = row_stream.try_next().await.expect("Failed to read resultset") {
            println!("row: {:?}", r.decompose_values().collect::<Vec<_>>());
        }

        println!("enumeration end: more_result={:?}", row_stream.has_more_resultset());
    }

    let stmt = client
        .prepare("Select * from test_data where id=?")
        .await
        .expect("Failed to prepare stmt");
    {
        let mut resultset_stream = client
            .fetch_all_statement(&stmt, &[(orcinus::protos::Value::Long(7), false)], true)
            .await
            .expect("Faield to execute stmt");
        let column_types = unsafe { resultset_stream.column_types_unchecked().collect::<Vec<_>>() };

        while let Some(r) = resultset_stream.try_next().await.expect("Failed to read resultset") {
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

    client.close_statement(stmt).await.expect("Failed to close statement");
    client.quit().await.expect("Failed to quit client");
}
