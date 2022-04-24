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
 */
void updateServerMigrationFrameOnPacketReceived(
    QuicClientConnectionState& connectionState,
    const QuicServerMigrationFrame& frame);

/**
 * Updates the connection state of the server when an acknowledgement
 * for a previously sent server migration frame is received.
 * @param connectionState  the server connection state.
 * @param frame            the acknowledged server migration frame.
 */
void updateServerMigrationFrameOnPacketAckReceived(
    QuicServerConnectionState& connectionState,
    const QuicServerMigrationFrame& frame);

} // namespace quic