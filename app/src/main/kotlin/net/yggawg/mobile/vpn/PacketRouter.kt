package net.yggawg.mobile.vpn

import kotlinx.coroutines.*
import net.yggawg.mobile.AppLogger
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * Userspace packet dispatcher sitting on the single TUN file descriptor.
 *
 * Routing table:
 *  1. IPv6 200::/7  → Yggdrasil overlay
 *  2. Everything else → AmneziaWG tunnel
 *
 * Yggdrasil peer IPs are excluded from the VPN routes at the Builder level
 * (excludeRoute on API 33+), so their traffic never enters the TUN.
 */
class PacketRouter(
    private val tunFd: android.os.ParcelFileDescriptor,
    private val ygg: YggdrasilManager,
    private val awg: AwgManager,
) {
    companion object {
        private const val TAG = "PacketRouter"
        private const val BUF_SIZE = 65536
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val outStream = FileOutputStream(tunFd.fileDescriptor)

    fun start() {
        scope.launch { readLoop() }
        AppLogger.i(TAG, "PacketRouter started")
    }

    fun stop() {
        scope.cancel()
        AppLogger.i(TAG, "PacketRouter stopped")
    }

    /** Write a packet back into the TUN (inbound from Yggdrasil or AWG). */
    fun writeToTun(packet: ByteArray, offset: Int, length: Int) {
        try {
            outStream.write(packet, offset, length)
        } catch (e: Exception) {
            AppLogger.w(TAG, "writeToTun: $e")
        }
    }

    // -------------------------------------------------------------------------
    // Read loop
    // -------------------------------------------------------------------------

    private fun readLoop() {
        val buf = ByteArray(BUF_SIZE)
        val stream = FileInputStream(tunFd.fileDescriptor)
        while (scope.isActive) {
            val len = try {
                stream.read(buf)
            } catch (e: Exception) {
                if (scope.isActive) AppLogger.w(TAG, "TUN read error: $e")
                break
            }
            if (len <= 0) continue
            dispatch(buf, len)
        }
    }

    private fun dispatch(packet: ByteArray, len: Int) {
        if (len == 0) return
        val version = (packet[0].toInt() and 0xF0) ushr 4

        if (version == 4) {
            if (len < 20) return
            awg.writePacketBuffer(packet, len)
        } else if (version == 6) {
            if (len < 40) return
            if (packet.parseIPv6DestIsYggdrasil()) {
                ygg.writePacketBuffer(packet, len)
            } else {
                awg.writePacketBuffer(packet, len)
            }
        }
    }

    // -------------------------------------------------------------------------
    // Packet parsing helpers
    // -------------------------------------------------------------------------

    private fun ByteArray.parseIPv6DestIsYggdrasil(): Boolean {
        if (size < 40) return false
        // The destination address starts at offset 24.
        // Yggdrasil addresses are 200::/7, so the first byte (offset 24) must match (byte & 0xFE) == 0x02.
        return (this[24].toInt() and 0xFE) == 0x02
    }
}
