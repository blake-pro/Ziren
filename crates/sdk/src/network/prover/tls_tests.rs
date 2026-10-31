use super::client_tls_config;
use super::stage_service::{
    stage_service_client::StageServiceClient,
    stage_service_server::{StageService, StageServiceServer},
    GenerateProofRequest, GenerateProofResponse, GetStatusRequest, GetStatusResponse,
};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use tokio::{net::TcpListener, sync::oneshot, time::Duration};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Endpoint, Identity, Server, ServerTlsConfig};

struct TestStage;

#[tonic::async_trait]
impl StageService for TestStage {
    async fn generate_proof(
        &self,
        _: tonic::Request<GenerateProofRequest>,
    ) -> Result<tonic::Response<GenerateProofResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not needed by this test"))
    }

    async fn get_status(
        &self,
        request: tonic::Request<GetStatusRequest>,
    ) -> Result<tonic::Response<GetStatusResponse>, tonic::Status> {
        Ok(tonic::Response::new(GetStatusResponse {
            proof_id: request.into_inner().proof_id,
            ..Default::default()
        }))
    }
}

#[tokio::test]
async fn https_clients_accept_custom_ca_and_reject_unknown_ca_and_wrong_name() {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("https://{address}");
    let identity = Identity::from_pem(certificate.pem(), key.serialize_pem());
    let (shutdown, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))
            .unwrap()
            .add_service(StageServiceServer::new(TestStage))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap())
        .resolve("localhost", address)
        .build()
        .unwrap();
    client.get(format!("https://localhost:{}", address.port())).send().await.unwrap();
    assert!(client.get(&url).send().await.is_err());
    let untrusted = reqwest::Client::builder()
        .use_rustls_tls()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .resolve("localhost", address)
        .build()
        .unwrap();
    assert!(untrusted.get(format!("https://localhost:{}", address.port())).send().await.is_err());

    let endpoint = Endpoint::from_shared(url).unwrap().connect_timeout(Duration::from_secs(5));
    let tls = client_tls_config("localhost".into(), Some(Certificate::from_pem(ca.pem()))).unwrap();
    let channel = endpoint.clone().tls_config(tls.clone()).unwrap().connect().await.unwrap();
    let response = StageServiceClient::new(channel)
        .get_status(GetStatusRequest { proof_id: "tls-control".into() })
        .await
        .unwrap();
    assert_eq!(response.into_inner().proof_id, "tls-control");
    assert!(endpoint
        .clone()
        .tls_config(tls.domain_name("wrong.example"))
        .unwrap()
        .connect()
        .await
        .is_err());
    assert!(endpoint
        .tls_config(client_tls_config("localhost".into(), None).unwrap())
        .unwrap()
        .connect()
        .await
        .is_err());

    drop(client);
    drop(untrusted);
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
}
