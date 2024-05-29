use kanidm_hsm_crypto::soft::SoftTpm;
use kanidm_hsm_crypto::{AuthValue, BoxedDynTpm, Tpm};
use msal::error::MsalError;
use msal::{BrokerClientApplication, EnrollAttrs};
use rpassword::read_password;
use std::io;
use std::io::Write;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use anyhow::{anyhow, Result};
use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FederationProvider {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    authority_host: String,
    graph: String,
}

async fn request_federation_provider(
    odc_provider: &str,
    domain: &str,
) -> Result<(String, String, String)> {
    let url = Url::parse_with_params(
        &format!("https://{}/odc/v2.1/federationProvider", odc_provider),
        &[("domain", domain)],
    )?;

    let resp = reqwest::get(url).await?;
    if resp.status().is_success() {
        let json_resp: FederationProvider = resp.json().await?;
        println!("Discovered tenant_id: {}", json_resp.tenant_id);
        println!("Discovered authority_host: {}", json_resp.authority_host);
        println!("Discovered graph: {}", json_resp.graph);
        Ok((
            json_resp.authority_host,
            json_resp.tenant_id,
            json_resp.graph,
        ))
    } else {
        Err(anyhow!(resp.status()))
    }
}

fn split_username(username: &str) -> Option<(&str, &str)> {
    let tup: Vec<&str> = username.split('@').collect();
    if tup.len() == 2 {
        return Some((tup[0], tup[1]));
    }
    None
}

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed setting up default tracing subscriber.");

    let mut username = String::new();
    print!("Please enter your EntraID username: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut username)
        .expect("Failed to read username");
    username = username.trim().to_string();

    let (_, domain) = split_username(&username).expect("Failed splitting username");

    let (authority_host, tenant_id, _graph) =
        request_federation_provider("odc.officeapps.live.com", &domain)
            .await
            .expect("Failed discovering tenant");

    let authority = format!("https://{}/{}", authority_host, tenant_id);
    println!("Creating the broker app");
    let mut app =
        BrokerClientApplication::new(Some(&authority), None, None).expect("Failed creating app");

    let exists = app
        .check_user_exists(&username)
        .await
        .expect("Failed checking if user exists");
    println!("User {} exists? {}", &username, exists);

    let scope = vec![];

    print!("{} password: ", &username);
    io::stdout().flush().unwrap();
    let password = match read_password() {
        Ok(password) => password,
        Err(e) => {
            println!("{:?}", e);
            return ();
        }
    };

    println!("Attempting device enrollment");
    let mut tpm = BoxedDynTpm::new(SoftTpm::new());
    let auth_str = AuthValue::generate().expect("Failed to create hex pin");
    let auth_value = AuthValue::from_str(&auth_str).expect("Unable to create auth value");
    // Request a new machine-key-context. This key "owns" anything
    // created underneath it.
    let loadable_machine_key = tpm
        .machine_key_create(&auth_value)
        .expect("Unable to create new machine key");
    let machine_key = tpm
        .machine_key_load(&auth_value, &loadable_machine_key)
        .expect("Unable to load machine key");
    let attrs = match EnrollAttrs::new(
        domain.to_string(),
        Some("test_machine".to_string()),
        None,
        Some(8),
        None,
    ) {
        Ok(attrs) => attrs,
        Err(e) => {
            println!("{:?}", e);
            return ();
        }
    };
    let mut mfa_req = match app
        .initiate_acquire_token_by_mfa_flow_for_device_enrollment(&username, &password)
        .await
    {
        Ok(mfa) => mfa,
        Err(e) => {
            println!("{:?}", e);
            return ();
        }
    };
    print!("{}", mfa_req.msg);
    io::stdout().flush().unwrap();
    let input = match read_password() {
        Ok(password) => password,
        Err(e) => {
            println!("{:?} ", e);
            return ();
        }
    };

    let token1 = match mfa_req.mfa_method.as_str() {
        "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => match app
            .acquire_token_by_mfa_flow(&username, Some(&input), None, &mut mfa_req)
            .await
        {
            Ok(token) => token,
            Err(e) => {
                println!("MFA FAIL: {:?}", e);
                return ();
            }
        },
        _ => {
            let mut poll_attempt = 1;
            let polling_interval = mfa_req.polling_interval.unwrap_or(5000);
            loop {
                match app
                    .acquire_token_by_mfa_flow(&username, None, Some(poll_attempt), &mut mfa_req)
                    .await
                {
                    Ok(token) => break token,
                    Err(e) => match e {
                        MsalError::MFAPollContinue => {
                            poll_attempt += 1;
                            sleep(Duration::from_millis(polling_interval.into()));
                            continue;
                        }
                        e => {
                            println!("MFA FAIL: {:?}", e);
                            return ();
                        }
                    },
                }
            }
        }
    };

    let (_transport_key, _cert_key, device_id) = match app
        .enroll_device(&token1, attrs, &mut tpm, &machine_key)
        .await
    {
        Ok((transport_key, cert_key, device_id)) => (transport_key, cert_key, device_id),
        Err(e) => {
            println!("{:?}", e);
            return ();
        }
    };
    println!("Enrolled with device id: {}", device_id);

    println!("Obtain PRT from enrollment refresh token");
    let token = match app
        .acquire_token_by_refresh_token(
            &token1.refresh_token,
            scope.clone(),
            None,
            &mut tpm,
            &machine_key,
        )
        .await
    {
        Ok(token) => token,
        Err(e) => {
            println!("{:?}", e);
            return ();
        }
    };
    println!(
        "access_token: {}, spn: {}, uuid: {:?}, mfa?: {:?}",
        token.access_token.clone().unwrap(),
        token.spn().unwrap(),
        token.uuid().unwrap(),
        token.amr_mfa().unwrap()
    );

    println!("Provision hello key");
    let win_hello_key = match app
        .provision_hello_for_business_key(&token1, &mut tpm, &machine_key, "123456")
        .await
    {
        Ok(win_hello_key) => win_hello_key,
        Err(e) => {
            println!("{:?}", e);
            return ();
        }
    };
    println!("{:?}", win_hello_key);

    println!("Acquire token via hello key");
    let token4 = match app
        .acquire_token_by_hello_for_business_key(
            &username,
            &win_hello_key,
            vec![],
            None,
            &mut tpm,
            &machine_key,
            "123456",
        )
        .await
    {
        Ok(token) => token,
        Err(e) => {
            println!("{:?}", e);
            return ();
        }
    };
    println!(
        "access_token: {}, spn: {}, uuid: {:?}, mfa?: {:?}",
        token4.access_token.clone().unwrap(),
        token4.spn().unwrap(),
        token4.uuid().unwrap(),
        token.amr_mfa().unwrap()
    );

    let _prt = match &token4.prt {
        Some(prt) => prt.clone(),
        None => {
            println!("Failed to find PRT in Hello token!");
            return ();
        }
    };
}
