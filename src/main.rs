//! Substrate Node Template CLI library.

#![warn(missing_docs)]
#![warn(unused_extern_crates)]

extern crate futures;
#[macro_use]
extern crate error_chain;
extern crate tokio;
#[macro_use]
extern crate log;
extern crate substrate_cli;
extern crate substrate_primitives as primitives;
extern crate substrate_consensus_aura as consensus;
extern crate substrate_client as client;
#[macro_use]
extern crate substrate_network as network;
#[macro_use]
extern crate substrate_executor;
extern crate substrate_transaction_pool as transaction_pool;
extern crate substrate_finality_grandpa as grandpa;
#[macro_use]
extern crate substrate_service;
extern crate multisig_node_runtime;
#[macro_use]
extern crate structopt;
#[macro_use]
extern crate srml_support;

mod chain_spec;
mod service;
mod cli;

pub use substrate_cli::{VersionInfo, IntoExit, error};

fn run() -> cli::error::Result<()> {
	let version = VersionInfo {
		commit: env!("VERGEN_SHA_SHORT"),
		version: env!("CARGO_PKG_VERSION"),
		executable_name: "multisig-node",
		author: "Eenae",
		description: "multisig-node",
	};
	cli::run(::std::env::args(), cli::Exit, version)
}

quick_main!(run);
