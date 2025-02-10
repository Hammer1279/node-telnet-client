# node-telnet-client [![Node.js CI](https://github.com/Hammer1279/node-telnet-client/actions/workflows/pkg.yml/badge.svg)](https://github.com/Hammer1279/node-telnet-client/actions/workflows/pkg.yml)

A zero dependency NodeJS Implementation of a [RFC-854](https://datatracker.ietf.org/doc/html/rfc854) telnet client.

This is a very early version that so far isn't very compatible with most major telnet servers yet.

It is developed for the [HTDev Telnet Server](telnet://ht-dev.de) for encrypted communication and extended functionality.

## Autorun command

Create a file called `batchrun.txt` in the same directory as the client, write each command on a separate line

## Installation

Just download the latest binary for your operating system from the releases page for the last stable version.
For experimental versions, check the pre-releases under releases, for "nightly" builds, check the actions for the latest build artifacts, they build for every commit.

## Run from Source

It has zero dependencies itself so to run a copy locally, just run it with `node index.js`

To build the application, run `npm install` and then `npm run build`.

## Build Dependencies

- @yao-pkg/pkg: Compiling the Application
- protocol-registry: Register the telnet uri as per [RFC-4248](https://datatracker.ietf.org/doc/html/rfc4248)
