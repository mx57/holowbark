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
    fun writeToTun(packet: ByteArray) {
        try {
            outStream.write(packet)
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

    private fun dispatch(buf: ByteArray, len: Int) {
        if (len <= 0) return

        val isYgg = when ((buf[0].toInt() and 0xF0) ushr 4) {
            4 -> {
                if (len < 20) return
                false
            }
            6 -> {
                if (len < 40) return
                // Yggdrasil overlay: 200::/7
                // First byte of IPv6 address with mask 0xFE == 0x02, i.e. byte ∈ {0x02, 0x03}.
                // IPv6 destination address is at bytes [24..39]
                (buf[24].toInt() and 0xFE) == 0x02
            }
            else -> return
        }

        val packet = buf.copyOf(len)
        if (isYgg) {
            ygg.writePacket(packet)
        } else {
            awg.writePacket(packet)
        }
    }
}
