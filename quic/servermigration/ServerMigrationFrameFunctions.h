#pragma once

#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/Types.h>
#include <quic/server/state/ServerStateMachine.h>

namespace quic {

/**
 * Initiates a send of the given server migration frame.
 * This function can be used only by a server.
 * @param connectionState  the server connection state.
 * @param frame            the server migration frame to send.
 */
void sendServerMigrationFrame(
    QuicServerConnectionState& connectionState,
    QuicServerMigrationFrame frame);

/**
 * Updates the connection state of the server when
 * a server migration frame is received.
 * @param connectionState  the server connection state.
 * @param frame            the received server migration frame.
 */
void updateServerMigrationFrameOnPacketReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame);

/**
 * Updates the connection state of the client when
 * a server migration frame is received.
 * @param connectionState  the client connection state.
 * @param frame            the received server migration frame.
 * @param packetNumber     the packet number of the packet carrying the frame.
 * @param peerAddress      the address of the peer.
 */
void updateServerMigrationFrameOnPacketReceived(
    QuicClientConnectionState& connectionState,
    const QuicServerMigrationFrame& frame,
    const PacketNum& packetNumber,
    const folly::SocketAddress& peerAddress);

/**
 * Updates the connection state of the server when an acknowledgement
 * for a previously sent server migration frame is received.
 * @param connectionState  the server connection state.
 * @param frame            the acknowledged server migration frame.
 * @param packetNumber     the packet number of the packet carrying
 *                         the acknowledgement.
 */
void updateServerMigrationFrameOnPacketAckReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame,
    const PacketNum& packetNumber);

/**
 * Updates the connection state after sending the given server migration frame.
 * @param connectionState  the connection state.
 * @param frame            the server migration frame that was sent.
 */
void updateServerMigrationFrameOnPacketSent(
    QuicConnectionStateBase& connectionState,
    const QuicServerMigrationFrame& frame);

/**
 * Updates the connection state on cloning the given server migration frame.
 * @param connectionState  the connection state.
 * @param frame            the server migration frame.
 * @return                 the updated server migration frame as simple frame.
 */
folly::Optional<QuicSimpleFrame> updateServerMigrationFrameOnPacketClone(
    QuicConnectionStateBase& connectionState,
    const QuicServerMigrationFrame& frame);

/**
 * Updates the connection state after the loss
 * of the given server migration frame.
 * @param connectionState  the connection state.
 * @param frame            the lost server migration frame.
 */
void updateServerMigrationFrameOnPacketLoss(
    QuicConnectionStateBase& connectionState,
    const QuicServerMigrationFrame& frame);

/**
 * Updates the server migration probing state on a probe timeout event.
 * It must be called only if a server migration protocol state has
 * already been created.
 * @param connectionState  the client connection state.
 */
void maybeUpdateServerMigrationProbing(
    QuicClientConnectionState& connectionState);

/**
 * Ends a server migration probing and starts a path validation, if a probing
 * is ongoing. It must be called only if a server migration protocol state has
 * already been created and the highest-numbered non-probing packet
 * has been received.
 * @param connectionState  the client connection state.
 * @param peerAddress      the address from which the highest-numbered
 *                         non-probing packet has been received.
 */
void maybeEndServerMigrationProbing(
    QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress);

/**
 * Detects if a Symmetric or Synchronized Symmetric migration is ongoing.
 * It must be called only when the highest-numbered non-probing packet
 * arrives from a new server address.
 * @param connectionState  the client connection state.
 * @param peerAddress      the address from which the highest-numbered
 *                         non-probing packet has been received. It must be
 *                         different from the current server address.
 * @param packetNumber     the packet number of the highest-numbered
 *                         non-probing packet.
 */
void maybeDetectSymmetricMigration(
    QuicClientConnectionState& connectionState,
    const folly::SocketAddress& peerAddress,
    const PacketNum& packetNumber);

/**
 * Ends a server migration, resetting the migration state. It must be called
 * only if a server migration protocol state has already been created and a path
 * validation involving a new server address has been successfully completed.
 * @param connectionState  the client connection state.
 * @param packetNumber     the packet number of the packet carrying the
 *                         PATH_RESPONSE frame.
 */
void endServerMigration(
    QuicClientConnectionState& connectionState,
    const PacketNum& packetNumber);

/**
 * Ends a server migration, resetting the migration state. It must be called
 * only if a server migration protocol state has already been created and the
 * path validation has been completed.
 * @param connectionState  the server connection state.
 * @param packetNumber     the packet number of the packet carrying the
 *                         acknowledgement for the PATH_RESPONSE frame.
 */
void endServerMigration(
    QuicServerConnectionState& connectionState,
    const PacketNum& packetNumber);

} // namespace quic
