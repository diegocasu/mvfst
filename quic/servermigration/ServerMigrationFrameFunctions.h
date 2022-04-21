#pragma once

#include <quic/codec/Types.h>
#include <quic/server/state/ServerStateMachine.h>

namespace quic {

/**
 * Initiate a send of the given server migration frame.
 * This function can be used only by a server.
 * @param connectionState  the server connection state.
 * @param frame            the server migration frame to send.
 */
void sendServerMigrationFrame(
    QuicServerConnectionState& connectionState,
    QuicServerMigrationFrame frame);

} // namespace quic
