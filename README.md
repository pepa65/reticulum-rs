[![dependencies](https://deps.rs/repo/github/pepa65/reticulum-rs/status.svg)](https://deps.rs/repo/github/pepa65/reticulum-rs)
[![license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/pepa65/reticulum-rs/blob/main/LICENSE)

# reticulum-rs 0.3.14
Package **reticulum-rs** is a Rust implementation of the [Reticulum Network Stack](https://reticulum.network/)
— a cryptographic, decentralised, and resilient mesh networking protocol designed for communication over any physical layer.

This project brings Reticulum's capabilities to the Rust ecosystem, enabling embedded,
and constrained deployments with maximum performance and minimal dependencies.

## Features
* 📡 Cryptographic mesh networking
* 🔐 Trustless routing via identity-based keys
* 📁 Lightweight and modular design
* 🧱 Support for multiple transport layers (TCP, serial, Kaonic)
* 🔌 Easily embeddable in embedded devices and tactical radios
* 🧪 Example clients for testnets and real deployments

## Structure
* `src`: Core Reticulum protocol implementation
* `proto`: Protocol definitions (e.g. for Kaonic)
* `examples`: Example clients and servers
  - kaonic_client
  - kaonic_tcp_mesh
  - kaonic_mesh
  - link_client
  - udp_link
  - tcp_client
  - tcp_server
  - testnet_client

## Getting Started
### Prerequisites
* Rust (edition 2024)
* `protoc` (package `protobuf-compiler`) for compiling `.proto` files (if using gRPC/Kaonic modules)

### Build
`cargo rel`

## Use Cases
* 🛰 Tactical radio mesh with Kaonic
* 🕵️‍♂️ Covert communication using serial or sub-GHz transceivers
* 🚁 UAV-to-ground resilient C2 and telemetry
* 🧱 Decentralized infrastructure-free messaging

## License
* This project is licensed under the MIT license.
* © Beechat Network Systems Ltd. All rights reserved. https://beechat.network
