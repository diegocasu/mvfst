![alt text](logo.png "MVFST")

## Overview

The repository contains an experimental implementation of QUIC server migration on top of `mvfst`, a production-grade
implementation of [IETF QUIC](https://quicwg.org/) by Meta.

The extension was developed as part of [_Extending mvfst to support enhanced server-side migration in QUIC: protocol
design and performance evaluation_](https://etd.adm.unipi.it/theses/available/etd-09062022-144126), a thesis for the
Master of Science in Computer Engineering at the University of Pisa.

The implementation offers:

- support for the `Explicit`, `Pool of Addresses`, and `Symmetric` migration protocols, including the
  `Proactive Explicit`, `Reactive Explicit`, and `Synchronized Symmetric` variants;
- negotiation of migration protocols during the handshake;
- server migration when multiple clients are connected to the same server.

## QUIC server migration

The currently standardized version of QUIC ([RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000)) allows client
migration only. Introducing server migration into QUIC enables a server to change address during a session, without
disrupting the connection or requiring an additional handshake with the client. Differently from TCP, this mechanism
allows preserving open connections during live relocation of server instances, removing the need of keeping the same IP
address across machines, employing SDN solutions to transparently redirect traffic, or re-establishing sessions at
application level. Migration is handled directly at transport level, so that relocation appears to an application as a
period of peer unreachability.

QUIC server migration can be realized adopting multiple protocols, also called strategies, which work at
**connection level**:

- `Explicit`, where the server is notified about an imminent migration, together with the destination address, by an
  external actor (e.g. an orchestrator). The address is shared with the client using a `SERVER_MIGRATION` frame, and the
  client is responsible for reaching the server at the new host by means of a polling mechanism based on standard QUIC
  probing. `Explicit` has two variants, called `Proactive Explicit` and `Reactive Explicit`: the former starts probing
  immediately after receiving the new server address, while the latter waits for the occurrence of a packet loss;
- `Pool of Addresses`, where the server is pre-configured with a set of possible destination addresses, which are shared
  with the client during the handshake using `POOL_MIGRATION_ADDRESS` frames. In this case, the server can be relocated
  without being notified, and the client is responsible for performing a cyclical probing of the possible destination
  addresses to identify the correct new host;
- `Symmetric`, which is based on server notifications sent upon restore from the new address by means of
  `SERVER_MIGRATED` frames. It removes migration probing and the need of knowing in advance the destination address. It
  has one variant, called `Synchronized Symmetric`, which advertises the imminent migration event to the client sending
  an empty `SERVER_MIGRATION` frame.

`Explicit` and `Pool of Addresses` were introduced in
[_Extending the QUIC Protocol to Support Live Container Migration at the
Edge_](https://ieeexplore.ieee.org/document/9469425) and
[_Server-side QUIC connection migration to support microservice deployment at the
edge_](https://www.sciencedirect.com/science/article/abs/pii/S157411922200030X), while `Symmetric` is a novel
contribution. More details about the strategies, as well as their sequence diagrams, can be found in the thesis.

## Migration protocol negotiation

The availability of multiple server migration protocols demands for a mechanism to choose which one will be used during
a session. The negotiation is designed to accomplish it by means of a custom transport parameter, called
`server_migration_suite`, exchanged by endpoints during the handshake. The client encodes its supported protocols, and
the server matches them with its ones, returning the set of negotiated protocols for the session. If the set is empty,
server migration is disabled for the session.

The negotiation can end up with a set of cardinality higher than one, if needed. For instance, if both endpoints support
`Explicit` and `Symmetric`, the negotiated set will contain both of them. In this implementation, the actual protocol
used during a migration is chosen by the user at server side (see the [tutorial](#notify-imminent-server-migration)),
while the client is able to recognise it by looking at the type of migration frames sent by the server. During the same
session, different migrations can be performed adopting different protocols, with the only exception of
`Pool of Addresses`: if it is negotiated, all the migrations must be done with `Pool of Addresses`.

## Server migration with multiple clients

Server migration protocols work at connection level, where there exist only a client and a server. However, a QUIC
server can communicate with multiple clients at the same time, namely it can have multiple ongoing connections.
Therefore, it is necessary to introduce a cross-connection synchronization procedure to be sure that all the clients are
ready to undergo a server migration.

The extension implements such a procedure in a way that allows using different migration protocols for different
connections. Moreover, it ensures that connections with clients not supporting server migration are handled like normal
QUIC connections until the relocation event. The multi-client synchronization consists in the following steps:

1. the server is notified by an external actor about an imminent server migration. For each connection, the server must
   receive the migration protocol to use and protocol-specific information like the destination address. The
   notification must be sent even in case of protocols like `Symmetric`;
2. the server blocks the new handshakes;
3. the server notifies the imminent server migration to each connection. Connections not supporting server migration are
   automatically closed;
4. each connection independently carries out the migration preparation, following the protocol requirements. For
   instance, connections adopting `Explicit` exchange `SERVER_MIGRATION` frames, while connections using `Symmetric`
   do nothing. Then, in an asynchronous way, connections report when they are ready to sustain a migration;
5. when all the connections are ready, the server declares its readiness for migration and can be relocated;
6. when the server is restored at destination, it is informed about the event by an external actor. Then, handshakes are
   unblocked and all the connections are notified about the restore. If a connection uses a protocol like `Symmetric`,
   it carries out the required steps to conclude the migration.

## Repository layout

The extension is available in the [`server-migration`](https://github.com/diegocasu/mvfst/tree/server-migration) branch.
The `main` branch represents the version of `mvfst` forked at the beginning of the development.

The majority of the additions are encapsulated into the `quic/servermigration` directory, which includes:

- client and server negotiators used during the handshake;
- a factory pattern to instantiate Pool of Addresses schedulers;
- the handling logic for server migration frames and events (e.g. management of migration probing);
- callbacks that can be registered by endpoints to get informed about server migration events;
- tests covering the previously mentioned features. In particular, `QuicServerMigrationIntegrationTest`
  comprises a set of integration tests employing full clients and servers able to reproduce negotiation, migration with
  different protocols, migration in presence of single or multiple clients, and so on.

Other additions and tests are scattered across the source files of `mvfst`. Examples of such additions are the
encoding/decoding of new frames, the introduction of negotiation into the handshake management, the invocation of server
migration frame functions during the packet processing, and the enhancement of endpoint states to track server migration
progress.

An overview of all the modified files can be found in the
[diff](https://github.com/facebookincubator/mvfst/compare/main...diegocasu:mvfst:server-migration).

## Getting started: client

### Enable/Disable server migration

Support for server migration is disabled by default and can be enabled working with the interface of
`QuicClientTransport`. To specify the supported protocols, it is enough to create a set containing them and pass it to
the transport. If `Pool of Addresses` is specified, it is possible to choose a factory to build a custom scheduler for
cyclical probing. This choice is optional: if nothing is specified, `DefaultPoolMigrationAddressSchedulerFactory` and
`DefaultPoolMigrationAddressScheduler` are employed. Both operations must be done before starting the transport with
the `start()` method.

```cpp
std::unordered_set<ServerMigrationProtocol> migrationProtocols;
migrationProtocols.insert(ServerMigrationProtocol::EXPLICIT);
migrationProtocols.insert(ServerMigrationProtocol::POOL_OF_ADDRESSES);
migrationProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
migrationProtocols.insert(ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);

auto quicClient = std::make_shared<QuicClientTransport>(...);
quicClient->allowServerMigration(migrationProtocols);
quicClient->setPoolMigrationAddressSchedulerFactory(
        std::make_unique<DefaultPoolMigrationAddressSchedulerFactory>());
```

### Set callbacks

Server migration events can be tracked using the asynchronous callbacks available in `quic/servermigration/Callbacks.h`.
In particular, a subset of the `ServerMigrationEventCallback` methods is dedicated to the client and can be passed to
the transport for later invocation. Callbacks must be set before starting the client and are executed by the transport
thread, so they must not include blocking operation. They are not strictly needed to handle server migration, but could
be useful to stop sending `STREAM` frames during the migration, implement `Proactive Explicit`, or simply debug.

```cpp
class ClientCallback : public ServerMigrationEventCallback {
    void onPoolMigrationAddressReceived(
            PoolMigrationAddressFrame frame) noexcept override {
        ...
    }
    
    void onServerMigrationReceived(ServerMigrationFrame frame) noexcept override {
        ...
    }
    
    void onServerMigratedReceived() noexcept override {
        ...
    }
    
    void onServerMigrationProbingStarted(
        ServerMigrationProtocol migrationProtocol,
        folly::SocketAddress address) noexcept override {
        ...
    }
    
    void onServerMigrationCompleted() noexcept override {
        ...
    }
};
```

```cpp
auto quicClient = std::make_shared<QuicClientTransport>(...);
auto clientCallback = std::make_shared<ClientCallback>();
quicClient->setServerMigrationEventCallback(clientCallback);
```

### Implement Proactive Explicit

`Proactive Explicit` and `Reactive Explicit` are variants adopted by the client only, because they determine when
probing towards the new server address should start. As such, negotiation involves only a generic `Explicit` protocol,
specified with `ServerMigrationProtocol::EXPLICIT`. At client side, the latter is equivalent to `Reactive Explicit`,
while `Proactive Explicit` must be implemented manually by simulating the occurrence of a PTO at the desired time. To do
so, it is enough to call `onProbeTimeout()` on `QuicClientTransport`:

```cpp
quicClient->onProbeTimeout();
```

It should be noted that the invocation does not trigger a true PTO, but only updates the probing state linked to server
migration, for instance changing the server address at transport level.

## Getting started: server

### Enable/Disable server migration

The steps are similar to the ones carried out by the client, this time involving `QuicServerTransport`. To enable the
support for server migration on a single connection, the set of supported protocols must be passed to the chosen
transport before it is started. An option is to do it immediately after the transport creation, hence inside a subclass
of `QuicServerTransportFactory`. If `Pool of Addresses` is among the protocols, the possible destination addresses must
be pre-configured as well.

```cpp
class TransportFactory : public QuicServerTransportFactory {
    QuicServerTransport::Ptr make(
            folly::EventBase* evb,
            std::unique_ptr<folly::AsyncUDPSocket> socket,
            const folly::SocketAddress&,
            QuicVersion,
            std::shared_ptr<const fizz::server::FizzServerContext> context) noexcept 
            override {
        auto transport = QuicServerTransport::make(...);
        
        std::unordered_set<ServerMigrationProtocol> migrationProtocols;
        migrationProtocols.insert(ServerMigrationProtocol::EXPLICIT);
        migrationProtocols.insert(ServerMigrationProtocol::SYMMETRIC);
        migrationProtocols.insert(ServerMigrationProtocol::SYNCHRONIZED_SYMMETRIC);
        transport->allowServerMigration(migrationProtocols);
        
        transport->addPoolMigrationAddress(
                QuicIPAddress(folly::SocketAddress("127.1.1.1", 1234)));
        transport->addPoolMigrationAddress(
                QuicIPAddress(folly::SocketAddress("127.1.1.2", 1234)));
        transport->addPoolMigrationAddress(
                QuicIPAddress(folly::SocketAddress("127.1.1.3", 1234)));
        ...
        return transport;
    }
};
```

```cpp
auto quicServer = QuicServer::createQuicServer();
quicServer->setQuicServerTransportFactory(std::make_unique<TransportFactory>());
```

### Set callbacks

Server migration events can be tracked using the callbacks defined in `quic/servermigration/Callbacks.h`, this time
involving both `ClientStateUpdateCallback` and `ServerMigrationEventCallback` classes. Defining the callbacks is not
mandatory, but is necessary in practice to correctly handle server migration, in particular to understand when a server
with multiple ongoing connections is actually ready to be migrated.

`ClientStateUpdateCallback` defines an interface for methods invoked by a `QuicServerTransport` object when the
corresponding client changes state in a way that could be significant for server migration. In this way, it is possible
to keep track of connected/disconnected clients and get notified when a client migration happens, for instance to
support client mobility by means of server migrations.

The subset of `ServerMigrationEventCallback` methods dedicated to the server is useful to track the progress of server
migration for each connection. It is possible to get notified when migration frames are acknowledged, when a connection
is ready to be migrated, when a connection encounters an error during migration preparation, and when a connection
completes the migration.

Callbacks must be passed to a `QuicServerTransport` instance before starting it and are executed by the transport
thread. It is enough to implement them in a single class, create a corresponding object, and pass its `shared_ptr` to
the transport. Callbacks invoked by different transports should be handled by a single object in a centralized way, for
instance to correctly detect when all connections are ready for server migration. As such, a callback can be invoked by
multiple threads at the same time, and its definition should take care of possible synchronization issues. Different
transports can be recognised by looking at the `ConnectionId` argument passed by the callback itself. Once a connection
is established, its server-side CID is notified with the `onHandshakeFinished()` callback; then, every callback
involving that transport will report the same CID, even if the actual CID used by endpoints changes due to migrations.

```cpp
class ServerCallback : public ClientStateUpdateCallback,
                       public ServerMigrationEventCallback {
    // ClientStateUpdateCallback methods.
    void onHandshakeFinished(
            folly::SocketAddress clientAddress,
            ConnectionId serverConnectionId,
            folly::Optional<std::unordered_set<ServerMigrationProtocol>>
            negotiatedProtocols) noexcept override {
        ...
    }
    
    void onClientMigrationDetected(
            ConnectionId serverConnectionId,
            folly::SocketAddress newClientAddress) noexcept override {
        ...
    }
    
    void onConnectionClose(ConnectionId serverConnectionId) noexcept override {
        ...
    }
    
    // ServerMigrationEventCallback methods.
    void onPoolMigrationAddressAckReceived(
        ConnectionId serverConnectionId,
        PoolMigrationAddressFrame frame) noexcept override {
        ...
    }
    
    void onServerMigrationAckReceived(
        ConnectionId serverConnectionId,
        ServerMigrationFrame frame) noexcept override {
        ...
    }
    
    void onServerMigratedAckReceived(
        ConnectionId serverConnectionId) noexcept override {
        ...
    }
    
    void onServerMigrationFailed(ConnectionId serverConnectionId,
                                 ServerMigrationError error) noexcept override {
        ...
    }
    
    void onServerMigrationReady(
        ConnectionId serverConnectionId) noexcept override {
        ...
    }
    
    void onServerMigrationCompleted(
        ConnectionId serverConnectionId) noexcept override {
        ...
    }
}
```

```cpp
auto transport = QuicServerTransport::make(...);
auto serverCallback = std::make_shared<ServerCallback>();
transport->setClientStateUpdateCallback(serverCallback);
transport->setServerMigrationEventCallback(serverCallback);
```

### Notify imminent server migration

A `QuicServer` is notified about an imminent migration by invoking its `onImminentServerMigration()` method. The latter
expects as argument one of the following alternatives:

1. a map specifying the migration protocol and the destination address for each connection. A connection is identified
   by the CID established during the handshake, and the destination address can be omitted if not required by the
   protocol. Connections not specified in the map are automatically closed;
2. a single protocol and destination address valid for all the connections. Again, the presence of the destination
   address depends on the protocol.

The first option allows finer control on connection migration, for instance enabling the use of different protocols for
different connections. The second option is more convenient when all connections use the same migration protocol. CIDs,
migration protocols, and destination addresses should be passed by an external actor through a custom API. Such
interface is not defined in the extension and should be implemented by the user as needed.

```cpp
auto quicServer = QuicServer::createQuicServer();
...

// In a real deployment, migration data could be received from an orchestrator.
ConnectionId cid1 = ...;
auto migrationProtocol1 = ServerMigrationProtocol::EXPLICIT;
QuicIPAddress migrationAddress = ...;

ConnectionId cid2 = ...;
auto migrationProtocol2 = ServerMigrationProtocol::SYMMETRIC;

QuicServer::ServerMigrationSettings migrationSettings;
migrationSettings[cid1] = std::make_pair(migrationProtocol1, migrationAddress);
migrationSettings[cid2] = std::make_pair(migrationProtocol2, folly::none);
quicServer->onImminentServerMigration(migrationSettings);
```

```cpp
auto quicServer = QuicServer::createQuicServer();
...

// Notify migration passing the destination address.
auto migrationProtocol = ServerMigrationProtocol::EXPLICIT;
QuicIPAddress migrationAddress = ...;
quicServer->onImminentServerMigration(migrationProtocol, migrationAddress);

// OR

// Notify migration without passing the destination address.
auto migrationProtocol = ServerMigrationProtocol::SYMMETRIC;
quicServer->onImminentServerMigration(migrationProtocol, folly::none);
```

After invoking `QuicServer::onImminentServerMigration()`, `QuicServerTransport::onImminentServerMigration()` is called
for each transport. The success or failure of the call is notified in an asynchronous way by means of
the `onServerMigrationReady()` or `onServerMigrationFailed()` callbacks, respectively. Connections that encounter an
error during migration preparation are closed, triggering `onConnectionClose()`.

The whole QUIC server becomes ready for migration when all connections are ready or closed: from this point on, the
server can be relocated. An option to perform migration is to use an external checkpoint and restore tool like
[`CRIU`](https://github.com/checkpoint-restore/criu), which is ideal for containerized servers.

### Notify server migration end

Once the migration is finished and the restore at destination is completed, the server must be informed about the event.
This is needed to unblock the handshakes and allow connections to carry out additional migration steps, like sending
`SERVER_MIGRATED` frames in `Symmetric`. Again, the server could be notified about the occurrence by an external actor
through a custom API.

`QuicServer` is informed about restore by invoking either `onNetworkSwitch()`or
`onNetworkSwitch(const folly::SocketAddress& newAddress)`. The first version must be used when the server IP address is
preserved across migrations (e.g. `0.0.0.0`) or changed transparently by the migration tool. The second one must be used
when UDP sockets held by `QuicServerWorker` instances must undergo explicit rebinding.

```cpp
auto quicServer = QuicServer::createQuicServer();
...
// After a successful restore, an orchestrator notifies 
// the server, which in turn notifies QuicServer.
quicServer->onNetworkSwitch();

// OR

// Notification with rebinding. The new address 
// should be received from an orchestrator.
folly::SocketAddress newAddress = ...;
quicServer->onNetworkSwitch(newAddress);
```

After invoking `QuicServer::onNetworkSwitch()`, `QuicServerTransport::onNetworkSwitch()` is called for each transport.
Connections notify the outcome of migration in an asynchronous way calling `onServerMigrationCompleted()` when the path
validation ends successfully. In case of validation failure, a connection is closed and triggers `onConnectionClose()`.
Tracking such events is useful to understand when the server becomes ready again to undergo a migration.

## Full example

An example of server migration is available
[here](https://github.com/diegocasu/proxygen/tree/main/proxygen/httpserver/samples/servermigration/app), where
relocation is enabled by `CRIU`. The application was developed to carry out the performance evaluation reported in the
thesis.

## Build and test

The extension has been built and tested on Ubuntu 18.04 and 20.04. It does not require additional dependencies with 
respect to standard `mvfst` and is built exactly as the original library, namely running:

```
./build_helper.sh
```

The new features are accompanied by more than 250 tests, considering both unit and integration ones. Tests
exploit `GoogleTest` and can be executed together with the original ones by running:

```
cd _build/build
make test
```

To run only tests relative to server migration, replace the `make test` command with:

```
ctest -R \
"ClientStateMachineTest.*Migration*|\
DecodeTest.*Migration*|\
DecodeTest.*Migrated*|\
QuicIPAddressTest|\
QuicWriteCodecTest.*Migration*|\
QuicWriteCodecTest.*Migrated*|\
QuicClientTransportTest.*Migration*|\
ServerTransportParametersTest.*Migration*|\
QuicServerWorkerTest.*Migration*|\
QuicServerWorkerTest.*NetworkSwitch*|\
QuicServerTest.*NetworkSwitch*|\
QuicServerTransportTest.*ServerMigration*|\
QuicServerTransportTest.*PoolMigration*|\
QuicServerTransportTest.*ClientStateUpdateCallback*|\
QuicServerTransportTest.*NetworkSwitch*|\
DefaultPoolMigrationAddressSchedulerTest|\
QuicServerMigrationNegotiatorClientTest|\
QuicServerMigrationNegotiatorServerTest|\
QuicServerMigrationFrameFunctionsTest|\
QuicServerMigrationIntegrationTest"
```

More information about building and testing is available in the original
[README](https://github.com/diegocasu/mvfst/blob/main/README.md).