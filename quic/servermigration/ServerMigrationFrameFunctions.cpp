#include <quic/servermigration/ServerMigrationFrameFunctions.h>

namespace quic {

void sendServerMigrationFrame(
    QuicServerConnectionState& connectionState,
    QuicServerMigrationFrame frame) {
  connectionState.pendingEvents.frames.emplace_back(std::move(frame));
}

} // namespace quic
