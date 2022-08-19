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
        let cert = x509_parser::parse_x509_certificate(&end_entity.0[..])
            .expect("invalid certificate format");
        println!("end entity subject: {}", cert.1.subject);

        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn main() {
    let mut cc = tokio_rustls::rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(std::sync::Arc::new(MysqlCertForceVerifier))
        .with_no_client_auth();
    cc.enable_sni = false;

    let pool = r2d2::Pool::new(orcinus::r2d2::MysqlConnection {
        addr: "127.0.0.1:3306",
        server_name: rustls::ServerName::try_from("localhost").expect("invalid host name"),
        con_info: orcinus::autossl_client::SSLConnectInfo {
            base: orcinus::ConnectInfo::new("root", "root").database("test"),
            ssl_config: std::sync::Arc::new(cc),
        },
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

        println!(
            "enumeration end: more_result={:?}",
            row_iter.has_more_resultset()
        );
    }

    let client = orcinus::r2d2::SharedPooledClient::share_from(client);
    let mut stmt = client
        .prepare("Select * from test_data where id=?")
        .expect("Failed to prepare stmt");
    let exec_resp = stmt
        .execute(&[(orcinus::protos::Value::Long(7), false)], true)
        .expect("Faield to execute stmt");

    {
        let mut c = client.lock();

        let column_count = match exec_resp {
            orcinus::protos::StmtExecuteResult::Resultset { column_count } => column_count,
            _ => unreachable!("unexpected select statement result"),
        };
        let mut resultset_iter = c
            .binary_resultset_iterator(column_count as _)
            .expect("Failed to load resultset heading columns");
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
}
