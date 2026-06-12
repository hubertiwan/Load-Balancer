# Load Balancer

A load balancer for client-server communication with dynamic server discovery, health checking, and intelligent request distribution.

## Overview

Distributes requests from a client pool across a pool of backend servers. The system automatically discovers backend servers via multicast, periodically checks their health, and forwards requests to the least loaded server.

## Technology Stack

- **Language:** C
- **Library:** socket
- **Transport Protocols:** TCP, SCTP
- **Message Format:** Binary TLV (Type-Length-Value)

## Architecture

### Core Modules

#### Load Balancer
- Registers and tracks backend servers
- Maintains list of active client-server connections
- Receives requests from clients and routes to appropriate backend
- Daemon mode with syslog integration

#### Backend Server
- Multicast-based registration
- Responds to health-check probes (SCTP)
- Implements echo service on demand

#### Interactive Client
- Connects to load balancer via TCP
- Sends requests and receives responses
- DNS support via getaddrinfo

#### Service Discovery Module (Multicast)
- Automatic server registration via multicast group
- Load balancer discovers and adds available nodes
- Dynamic pool management without static configuration

#### Health-Check Module
- Periodic server probing (SCTP)
- Monitors server status and load
- Removes unresponsive nodes
- Restores healthy nodes to pool

### Shared Registry

Centralized data store maintained by load balancer:
- List of available backend servers
- Server load information
- Client-backend session mapping
- Concurrent access from client, discovery, and health-check modules

## Communication Protocols

### Multicast
- Automatic server discovery
- Service announcement and detection

### Unicast
- **Client ↔ Load Balancer:** TCP
- **Load Balancer ↔ Backend (health-check & control):** SCTP

### Message Format

All messages use TLV (Type-Length-Value) encoding:
- Node registration
- Load reports
- Client requests/responses

## Features

- ✓ Dynamic server discovery via multicast
- ✓ Load-aware request distribution (least loaded server)
- ✓ Periodic health checking
- ✓ Automatic node addition/removal
- ✓ Asynchronous client-server communication
- ✓ Daemon mode with system logging
- ✓ DNS support for client endpoints

## Communication Flows

### Server Registration (Multicast)
Backend server broadcasts presence to multicast group; load balancer receives announcement and adds node to pool.

### Health Checking (SCTP)
Load balancer periodically sends SCTP probes to backends; servers respond with status and load metrics.

### Client Requests (TCP)
Client connects to load balancer via TCP, sends request with server type identifier, load balancer forwards to most suitable backend.

## Logging

Load balancer logs to syslog:
- Node addition/removal events
- Load distribution decisions
- Error conditions and exceptions

