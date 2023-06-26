mod config;
mod node;

use std::collections::BTreeMap;
use crate::config::Export as _;
use crate::config::{Committee, Secret};
use crate::node::Node;
use clap::{crate_name, crate_version, App, AppSettings, SubCommand};
use consensus::Committee as ConsensusCommittee;
use crypto::SecretShare;
use env_logger::Env;
use futures::future::join_all;
use log::error;
use mempool::Committee as MempoolCommittee;
use threshold_crypto::SecretKeySet;
use threshold_crypto::serde_impl::SerdeSecret;
use std::fs;
use bincode::deserialize;
use tokio::task::JoinHandle;

#[tokio::main]
async fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of the sMVBA protocol.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("keys")
                .about("Print a fresh key pair to file")
                .args_from_usage("--filename=<FILE> 'The file where to print the new key pair'"),
        )
        .subcommand(
            SubCommand::with_name("threshold_keys")
                .about("Print fresh threshold key pairs to files")
                .args_from_usage("--filename=<FILE>... 'The files where to print the new key pairs'"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Runs a single node")
                .args_from_usage("--keys=<FILE> 'The file containing the node keys'")
                .args_from_usage("--threshold_keys=<FILE> 'The file containing the node threshold_keys'")
                .args_from_usage("--committee=<FILE> 'The file containing committee information'")
                .args_from_usage("--parameters=[FILE] 'The file containing the node parameters'")
                .args_from_usage("--store=<PATH> 'The path where to create the data store'"),
        )
        .subcommand(
            SubCommand::with_name("deploy")
                .about("Deploys a network of nodes locally")
                .args_from_usage("--nodes=<INT> 'The number of nodes to deploy'"),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let log_level = match matches.occurrences_of("v") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or(log_level));
    #[cfg(feature = "benchmark")]
    logger.format_timestamp_millis();
    logger.init();

    match matches.subcommand() {
        ("keys", Some(subm)) => {
            let filename = subm.value_of("filename").unwrap();
            if let Err(e) = Node::print_key_file(&filename) {
                error!("{}", e);
            }
        }
        ("threshold_keys", Some(subm)) => {
            let filenames: Vec<&str> = subm.values_of("filename").unwrap().collect();
            if let Err(e) = Node::print_threshold_key_file(filenames) {
                error!("{}", e);
            }
        }
        ("run", Some(subm)) => {
            let key_file = subm.value_of("keys").unwrap();
            let threshold_key_file = subm.value_of("threshold_keys").unwrap();
            let committee_file = subm.value_of("committee").unwrap();
            let parameters_file = subm.value_of("parameters");
            let store_path = subm.value_of("store").unwrap();
            match Node::new(committee_file, key_file, threshold_key_file, store_path, parameters_file).await {
                Ok(mut node) => {
                    tokio::spawn(async move {
                        node.analyze_block().await;
                    })
                    .await
                    .expect("Failed to analyze committed blocks");
                }
                Err(e) => error!("{}", e),
            }
        }
        ("deploy", Some(subm)) => {
            let nodes = subm.value_of("nodes").unwrap();
            match nodes.parse::<usize>() {
                Ok(nodes) if nodes > 0 => match deploy_testbed(nodes) {
                    Ok(handles) => {
                        let _ = join_all(handles).await;
                    }
                    Err(e) => error!("Failed to deploy testbed: {}", e),
                },
                _ => error!("The number of nodes must be a positive integer"),
            }
        }
        _ => unreachable!(),
    }
}

fn deploy_testbed(nodes: usize) -> Result<Vec<JoinHandle<()>>, Box<dyn std::error::Error>> {
    let keys: Vec<_> = (0..nodes).map(|_| Secret::new()).collect();

    // Print the committee file.
    let epoch = 1;
    let mempool_committee = MempoolCommittee::new(
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let name = key.name;
                let front = format!("127.0.0.1:{}", 13000 + i).parse().unwrap();
                let mempool = format!("127.0.0.1:{}", 13100 + i).parse().unwrap();
                (name, front, mempool)
            })
            .collect(),
        epoch,
    );
    let consensus_committee = ConsensusCommittee::new(
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let name = key.name;
                let stake = 1;
                let addresses = format!("127.0.0.1:{}", 13200 + i).parse().unwrap();
                (name, i, stake, addresses)  // daniel: not implemented for tss yet
            })
            .collect(),
        epoch,
    );
    let committee_file = "committee.json";
    let _ = fs::remove_file(committee_file);
    Committee {
        mempool: mempool_committee,
        consensus: consensus_committee,
    }
    .write(committee_file)?;

    // Prepare for threshold secret shares.
    let mut rng = rand::thread_rng();
    let sk_set = SecretKeySet::random((nodes-1)/3, &mut rng);
    let pk_set = sk_set.public_keys();

    // Write the key files and spawn all nodes.
    keys.iter()
        .enumerate()
        .map(|(i, keypair)| {
            // Write secret key file.
            let sk_file = format!("node_sk_{}.json", i);
            let _ = fs::remove_file(&sk_file);
            keypair.write(&sk_file)?;

            // Write secret key share file.
            let tss_file = format!("node_tss_{}.json", i);
            let _ = fs::remove_file(&tss_file);
            let tss = SecretShare { 
                id: i, 
                name: pk_set.public_key_share(i), 
                secret: SerdeSecret(sk_set.secret_key_share(i)), 
                pkset: pk_set.clone(),
            };
            tss.write(&tss_file)?;

            let store_path = format!("db_{}", i);
            let _ = fs::remove_dir_all(&store_path);

            Ok(tokio::spawn(async move {
                match Node::new(committee_file, &sk_file, &tss_file, &store_path, None).await { // daniel: not implemented for tss yet
                    Ok(mut node) => {
                        // Sink the commit channel.
                        while node.commit.recv().await.is_some() {}
                    }
                    Err(e) => error!("{}", e),
                }
            }))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()
}
