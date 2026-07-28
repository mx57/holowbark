package net.yggawg.mobile.vpn

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkAddress
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import net.yggawg.mobile.AppLogger
import net.yggawg.mobile.MainActivity
import net.yggawg.mobile.R
import net.yggawg.mobile.HolowbarkApp
import net.yggawg.mobile.config.AwgConfig
import net.yggawg.mobile.config.parseAwgConf
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

class YggVpnService : VpnService() {

    companion object {
        private const val TAG = "YggVpnService"
        private const val NOTIF_ID = 1

        const val ACTION_START       = "net.yggawg.mobile.START_VPN"
        const val ACTION_STOP        = "net.yggawg.mobile.STOP_VPN"
        const val ACTION_STATUS      = "net.yggawg.mobile.VPN_STATUS"
        const val ACTION_RESTART_AWG = "net.yggawg.mobile.RESTART_AWG"

        // Extras for ACTION_START intent
        const val EXTRA_AWG_CONF   = "awg_conf"
        const val EXTRA_YGG_PEERS  = "ygg_peers"      // ArrayList<String> of peer addresses
        const val EXTRA_YGG_KEY    = "ygg_key"
        const val EXTRA_MULTICAST  = "ygg_multicast"  // boolean

        // Community Yggdrasil DNS resolvers (Revertron). Support ICANN, ALFIS, OpenNIC, ad blocking.
        // All in 200::/7 — routed through Yggdrasil overlay automatically.
        val YGG_DNS_SERVERS = listOf(
            "308:62:45:62::",   // Amsterdam
            "308:84:68:55::",   // Frankfurt
            "308:25:40:bd::",   // Bratislava
            "308:26:d:c8::",    // Amsterdam 2
        )
    }

    private var status = TunnelStatus()
    private var router: PacketRouter? = null
    private var awgMgr: AwgManager?   = null
    private var yggMgr: YggdrasilManager? = null

    // Job specifically for the AWG keepalive hack
    private var keepaliveJob: kotlinx.coroutines.Job? = null
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Calling startForeground immediately to avoid ForegroundServiceDidNotStartInTimeException
        startForeground(NOTIF_ID, buildNotification(status))

        return when (intent?.action) {
            ACTION_STOP        -> { stopVpn(); stopSelf(); START_NOT_STICKY }
            ACTION_RESTART_AWG -> { restartAwg(); START_STICKY }
            else -> {
                val awgConfText = intent?.getStringExtra(EXTRA_AWG_CONF)
                @Suppress("UNCHECKED_CAST")
                val yggPeers   = intent?.getStringArrayListExtra(EXTRA_YGG_PEERS) ?: arrayListOf()
                val yggKey     = intent?.getStringExtra(EXTRA_YGG_KEY) ?: ""
                val multicast  = intent?.getBooleanExtra(EXTRA_MULTICAST, false) ?: false
                val awgConfig  = awgConfText?.let { runCatching { parseAwgConf(it) }.getOrNull() }
                startVpn(awgConfig, yggPeers, yggKey, multicast)
                START_STICKY
            }
        }
    }

    override fun onDestroy() {
        stopVpn()
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        AppLogger.w(TAG, "VPN permission revoked by system or user")
        stopVpn()
        super.onRevoke()
    }

    // -------------------------------------------------------------------------
    // Core Logic
    // -------------------------------------------------------------------------

    private fun startVpn(awgConfig: AwgConfig?, peers: List<String>, yggKey: String, multicast: Boolean) {
        if (status.overall != VpnState.IDLE && status.overall != VpnState.DISCONNECTED && status.overall != VpnState.ERROR) {
            return
        }
        AppLogger.i(TAG, "startVpn peers=${peers.size} awg=${awgConfig?.endpoint} multicast=$multicast")
        updateStatus { copy(ygg = LayerState.STARTING, awg = LayerState.STARTING, overall = VpnState.CONNECTING) }
        YggServiceAccess.manager = null

        val peerIps: Set<InetAddress> = peers.flatMap { parsePeerHosts(it) }.toSet()

        // Start Yggdrasil before establish() so we get the real overlay address
        // (derived from the private key) to assign to the TUN interface.
        // All callbacks use nullable vars (router?, awg?) so starting before those
        // are initialised is safe — packets are dropped until the router is ready,
        // which is fine during the brief setup window.
        val awgServerAddrBytes = awgConfig?.let { parseYggAddrBytes(it.endpoint) }
        val awgServerPort      = awgConfig?.let { parseEndpointPort(it.endpoint) } ?: 44555

        val awgMgr = AwgManager(
            onPacketOut    = { router?.writeToTun(it) },
            onStatusChange = { state -> updateStatus { copy(awg = state) } },
        )
        val yggMgr = YggdrasilManager(
            onPacketOut = { router?.writeToTun(it) },
            onWGPacket  = if (awgServerAddrBytes != null) { wgPkt ->
                awgMgr.sendWGPacket(wgPkt)
            } else null,
            onStatusChange = { state, addr, count ->
                updateStatus { copy(ygg = state, yggAddress = addr, yggPeers = count) }
            },
        )
        if (awgServerAddrBytes != null) {
            yggMgr.wgServerAddr = awgServerAddrBytes
            val addrHex = awgServerAddrBytes.joinToString(":") { "%02x".format(it) }
            AppLogger.i(TAG, "WG bridge: server=${awgConfig!!.endpoint} port=$awgServerPort addrBytes=[$addrHex]")
        } else {
            AppLogger.w(TAG, "AWG endpoint is not a Yggdrasil address — WG bridge disabled")
        }
        yggMgr.start(peers, yggKey, multicast)

        // The overlay address is deterministic from the private key — available immediately
        // after startJSON(), no need to wait for peer connections.
        val yggAddress = yggMgr.getAddress().ifEmpty { "200::" }
        AppLogger.i(TAG, "Yggdrasil address: $yggAddress")

        val physicalHasIPv6: Boolean = hasPhysicalIPv6()
        AppLogger.i(TAG, "physicalHasIPv6=$physicalHasIPv6")

        // Separate exclusions by address family.
        // IPv6 peer exclusions only make sense when the physical network has IPv6.
        val ipv4Exclusions: Set<Inet4Address> = peerIps.filterIsInstance<Inet4Address>().toSet()
        val ipv6Exclusions: Set<Inet6Address> = if (physicalHasIPv6) {
            peerIps.filterIsInstance<Inet6Address>().toSet()
        } else {
            val skipped = peerIps.filterIsInstance<Inet6Address>()
            if (skipped.isNotEmpty()) {
                AppLogger.w(TAG, "Physical network has no IPv6 — ${skipped.size} IPv6 peer(s) will " +
                                 "be unreachable: ${skipped.joinToString { it.hostAddress ?: "?" }}")
            }
            emptySet()
        }

        val builder = Builder()
            .setSession("Holowbark")
            .setMtu(1500)

        // Add WG client addresses from config (e.g. "10.9.0.2/32" or "172.16.0.2/32, fd01::2/128")
        val wgAddresses = mutableListOf<String>()
        awgConfig?.address?.let { raw ->
            // Split comma-separated addresses: "10.9.0.2/32, fd01::2/128" → ["10.9.0.2/32", "fd01::2/128"]
            val parts = raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            for (part in parts) {
                val slash = part.indexOf('/')
                val ip     = if (slash >= 0) part.substring(0, slash).trim() else part
                val defaultPrefix = if (":" in ip) 128 else 32
                val prefix = if (slash >= 0) part.substring(slash + 1).trim().toIntOrNull() ?: defaultPrefix else defaultPrefix
                runCatching { builder.addAddress(ip, prefix) }
                    .onFailure { AppLogger.w(TAG, "addAddress $ip/$prefix: $it") }
                    .onSuccess { wgAddresses.add(ip) }
            }
        }
        if (wgAddresses.isEmpty()) {
            builder.addAddress("10.100.0.1", 32)
        }
        // Use the real Yggdrasil address so replies to user-initiated connections
        // are routed correctly through the overlay back to this node.
        // Always use /128 (host address) because /7 crashes the system's
        // VpnManagerService.establishVpn call on many Android versions.
        // Skip if we are connecting to a standard WARP/WG server (awgServerAddrBytes == null)
        // because adding Yggdrasil addresses/routes without overlay functionality causes crashes
        // on some devices when the interface is brought up.
        if (yggKey.isNotEmpty() || awgServerAddrBytes != null) {
            if (yggAddress.isNotEmpty() && yggAddress != "200::") {
                runCatching { builder.addAddress(yggAddress, 128) }
                    .onFailure { AppLogger.w(TAG, "addAddress $yggAddress/128 failed: $it") }
            } else {
                AppLogger.w(TAG, "No valid Yggdrasil address — skipping IPv6 TUN address")
            }
            // Tricks Android's DNS resolver into issuing AAAA queries even when there is no
            // global IPv6 on the physical network. Without this single /128 host route the
            // resolver skips AAAA lookups entirely, making Yggdrasil service names unresolvable.
            // See android.googlesource.com/.../bionic/libc/dns/net/getaddrinfo.c#1935
            runCatching { builder.addRoute("2000::", 128) }
                .onFailure { AppLogger.w(TAG, "addRoute 2000::/128 failed: $it") }
        } else {
            AppLogger.i(TAG, "Non-Yggdrasil endpoint — skipping Yggdrasil TUN address & route setup")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // API 33+: catch-all routes + excludeRoute per IP (no route-count explosion).
            builder.addRoute("0.0.0.0", 0)
            if (physicalHasIPv6 || wgAddresses.any { ":" in it }) {
                builder.addRoute("::", 0)
            }
            (ipv4Exclusions + ipv6Exclusions).forEach { ip ->
                val prefix = if (ip is Inet4Address) 32 else 128
                runCatching { builder.excludeRoute(IpPrefix(ip, prefix)) }
                    .onFailure { AppLogger.w(TAG, "excludeRoute $ip: $it") }
            }
            AppLogger.i(TAG, "Routes: catch-all + ${ipv4Exclusions.size} IPv4 + ${ipv6Exclusions.size} IPv6 exclusions (API 33+)")
        } else {
            // API < 33: excludeRoute unavailable — use route-splitting.
            // IPv4: max 32 routes per excluded IP.
            val ipv4Base = listOf(Route(InetAddress.getByAddress(byteArrayOf(0, 0, 0, 0)), 0))
            val ipv4Routes = buildRoutesExcluding(ipv4Base, ipv4Exclusions)
            ipv4Routes.forEach { r ->
                runCatching { builder.addRoute(r.address.hostAddress ?: return@forEach, r.prefix) }
                    .onFailure { AppLogger.w(TAG, "addRoute ${r.address.hostAddress}/${r.prefix}: $it") }
            }
            // IPv6: route-splitting only when physical IPv6 is available (max 128 routes per IP).
            if (ipv6Exclusions.isNotEmpty()) {
                val ipv6Base = listOf(Route(InetAddress.getByAddress(ByteArray(16)), 0))
                val ipv6Routes = buildRoutesExcluding(ipv6Base, ipv6Exclusions)
                ipv6Routes.forEach { r ->
                    runCatching { builder.addRoute(r.address.hostAddress ?: return@forEach, r.prefix) }
                        .onFailure { AppLogger.w(TAG, "addRoute [${r.address.hostAddress}]/${r.prefix}: $it") }
                }
                AppLogger.i(TAG, "Routes: split IPv4 (${ipv4Routes.size}) + split IPv6 (${ipv6Routes.size}), excl ${ipv4Exclusions.size}+${ipv6Exclusions.size} (API<33)")
            } else {
                if (physicalHasIPv6 || wgAddresses.any { ":" in it }) {
                    builder.addRoute("::", 0)
                }
                AppLogger.i(TAG, "Routes: split IPv4 (${ipv4Routes.size}) + ::/0, excl ${ipv4Exclusions.size} IPv4 (API<33, no phys IPv6)")
            }
        }

        // AWG-provided DNS (private resolver behind the tunnel)
        awgConfig?.dns?.split(",")
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.forEach {
                runCatching { builder.addDnsServer(it) }
                    .onFailure { AppLogger.w(TAG, "addDnsServer $it: $it") }
            }
        // Yggdrasil community DNS resolvers — only added when enabled by the user.
        // These are in 200::/7 and go through the Yggdrasil overlay automatically.
        val yggDnsEnabled = getSharedPreferences("yggawg", android.content.Context.MODE_PRIVATE)
            .getBoolean("ygg_dns_enabled", false)
        if (yggDnsEnabled) {
            YGG_DNS_SERVERS.forEach { dns ->
                runCatching { builder.addDnsServer(dns) }
                    .onFailure { AppLogger.w(TAG, "addDnsServer Ygg $dns: $it") }
            }
            AppLogger.i(TAG, "Yggdrasil DNS enabled (${YGG_DNS_SERVERS.size} resolvers)")
        }
        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            AppLogger.e(TAG, "builder.establish() failed: ${e.message} — ${e.javaClass.name}")
            null
        }
        if (fd == null) {
            AppLogger.e(TAG, "establish() returned null — VPN permission not granted or failed")
            yggMgr.stop()
            updateStatus { copy(overall = VpnState.ERROR) }
            stopForeground(STOP_FOREGROUND_REMOVE)
            return
        }

        this.yggMgr = yggMgr
        this.awgMgr = awgMgr
        this.router = PacketRouter(fd, yggMgr, awgMgr)
        YggServiceAccess.manager = yggMgr
        router?.start()

        if (awgConfig != null) {
            awgMgr.start(awgConfig)
            if (awgServerAddrBytes != null) {
                // If the endpoint is an Yggdrasil address, start a keepalive coroutine
                // that injects packets into AWG to trigger handshake over the bridge.
                startKeepaliveHacks(awgMgr, yggMgr, awgServerAddrBytes, awgServerPort)
            }
        } else {
            AppLogger.w(TAG, "No AWG config provided — running Yggdrasil-only mode")
        }
    }

    private fun stopVpn() {
        if (status.overall == VpnState.IDLE || status.overall == VpnState.DISCONNECTED) return
        AppLogger.i(TAG, "stopVpn")

        keepaliveJob?.cancel()
        keepaliveJob = null

        router?.stop()
        awgMgr?.stop()
        yggMgr?.stop()
        router = null
        awgMgr = null
        yggMgr = null
        YggServiceAccess.manager = null

        updateStatus { TunnelStatus(overall = VpnState.DISCONNECTED) }
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun restartAwg() {
        AppLogger.i(TAG, "restartAwg")
        val mgr = awgMgr
        if (mgr == null) {
            AppLogger.w(TAG, "restartAwg: awgMgr is null")
            return
        }
        val confText = getSharedPreferences("yggawg", android.content.Context.MODE_PRIVATE)
            .getString("awg_conf", null)
        if (confText == null) {
            AppLogger.w(TAG, "restartAwg: no config")
            return
        }
        val cfg = runCatching { parseAwgConf(confText) }.getOrNull() ?: return
        mgr.stop()
        updateStatus { copy(awg = LayerState.STARTING, overall = VpnState.CONNECTING) }
        mgr.start(cfg)
    }

    // -------------------------------------------------------------------------
    // Hacks for bridging
    // -------------------------------------------------------------------------

    private fun startKeepaliveHacks(
        awgMgr: AwgManager,
        yggMgr: YggdrasilManager,
        serverAddrBytes: ByteArray,
        serverPort: Int,
    ) {
        keepaliveJob?.cancel()
        keepaliveJob = scope.launch(Dispatchers.IO) {
            // 1. Wait for Yggdrasil to connect to at least one peer
            AppLogger.d(TAG, "KeepaliveHack: waiting for Ygg peers...")
            try {
                YggNetworkState.peers.first { it.any { p -> p.up } }
            } catch (e: Exception) {
                AppLogger.d(TAG, "KeepaliveHack: peers wait aborted")
                return@launch
            }
            AppLogger.d(TAG, "KeepaliveHack: Ygg is up, starting dummy ping loop")

            // 2. Continually inject dummy pings into AWG to force Handshake Initiation packets
            // out of the Go layer, so we can wrap and send them through Yggdrasil.
            val triggerJob = launch {
                val dummyPkt = buildDummyIPv4()
                while (isActive) {
                    awgMgr.writePacket(dummyPkt)
                    delay(3_000)
                }
            }

            // 3. Read encrypted WG packets (handshake attempts) from AWG layer,
            // wrap in IPv6 UDP, and send via Yggdrasil overlay.
            var wgPktCount = 0
            while (isActive) {
                val wgPkt = awgMgr.recvWGPacket() ?: break
                if (wgPkt.isEmpty()) continue
                wgPktCount++
                val ourAddrStr   = yggMgr.getAddress()
                val ourAddrBytes = parseYggSelfAddr(ourAddrStr)
                if (ourAddrBytes == null) {
                    AppLogger.w(TAG, "AWG bridge: our Ygg address not available yet, skipping pkt #$wgPktCount")
                    continue
                }
                val ipPkt = buildIPv6UDP(
                    srcAddr = ourAddrBytes,
                    dstAddr = serverAddrBytes,
                    srcPort = WG_LOCAL_PORT,
                    dstPort = serverPort,
                    payload = wgPkt,
                )
                yggMgr.writePacket(ipPkt)
            }
            triggerJob.cancel()
            AppLogger.i(TAG, "AWG→Ygg bridge exited after $wgPktCount packet(s)")
        }
    }

    private fun parsePeerHosts(uri: String): List<InetAddress> {
        val host = uri.substringAfter("://").substringBefore(':').trim('[', ']')
        return runCatching { InetAddress.getAllByName(host).toList() }.getOrDefault(emptyList())
    }

    /**
     * True if the active network has at least one global IPv6 address.
     * Used to decide whether to add `::/0` and IPv6 exclusion routes.
     */
    private fun hasPhysicalIPv6(): Boolean {
        val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = cm.activeNetwork ?: return false
        val props = cm.getLinkProperties(network) ?: return false

        // Look for global IPv6 addresses (not link-local fe80::/10, not loopback ::1)
        for (linkAddr: LinkAddress in props.linkAddresses) {
            val addr = linkAddr.address
            if (addr is Inet6Address) {
                if (!addr.isLinkLocalAddress && !addr.isLoopbackAddress) {
                    return true
                }
            }
        }
        return false
    }

    // -------------------------------------------------------------------------
    // State management
    // -------------------------------------------------------------------------

    private fun updateStatus(modify: TunnelStatus.() -> TunnelStatus) {
        val s = status.modify()
        val overall = when {
            s.overall == VpnState.ERROR -> VpnState.ERROR
            s.awg == LayerState.UP      -> VpnState.CONNECTED
            s.awg == LayerState.ERROR || s.ygg == LayerState.ERROR -> VpnState.ERROR
            else -> s.overall
        }
        status = s.copy(overall = overall)
        AppLogger.d(TAG, "updateStatus: ygg=${s.ygg} awg=${s.awg} → overall=$overall")
        broadcastStatus()
        if (overall == VpnState.CONNECTED || overall == VpnState.CONNECTING || overall == VpnState.ERROR) {
            val notif = buildNotification(status)
            val mgr = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
            mgr.notify(NOTIF_ID, notif)
        }
    }

    private fun broadcastStatus() {
        val s = status
        getSharedPreferences("yggawg", android.content.Context.MODE_PRIVATE)
            .edit().putString("vpn_state", s.overall.name).apply()
        sendBroadcast(Intent(ACTION_STATUS).apply {
            setPackage(packageName)
            putExtra(TunnelStatus.EXTRA_OVERALL,     s.overall.name)
            putExtra(TunnelStatus.EXTRA_YGG,         s.ygg.name)
            putExtra(TunnelStatus.EXTRA_YGG_ADDRESS, s.yggAddress)
            putExtra(TunnelStatus.EXTRA_YGG_PEERS,   s.yggPeers)
            putExtra(TunnelStatus.EXTRA_AWG,         s.awg.name)
        })
        // Re-post notification on every broadcast so it reappears after being
        // swiped away (Android 14 allows dismissing FGS notifications).
        if (s.overall != VpnState.IDLE && s.overall != VpnState.DISCONNECTED) {
            val mgr = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
            mgr.notify(NOTIF_ID, buildNotification(s))
        }
    }

    // -------------------------------------------------------------------------
    // Notification
    // -------------------------------------------------------------------------

    private fun buildNotification(s: TunnelStatus): Notification {
        val text = when (s.overall) {
            VpnState.CONNECTED  -> "Ygg: ${s.yggAddress} | peers: ${s.yggPeers}"
            VpnState.CONNECTING -> "Connecting…"
            VpnState.ERROR      -> "Error"
            else                -> "Connecting…"
        }
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, YggVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = NotificationCompat.Builder(this, HolowbarkApp.VPN_NOTIF_CHANNEL)
            .setContentTitle("Holowbark")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(openIntent)
            .setOngoing(true)
        if (s.overall == VpnState.CONNECTED || s.overall == VpnState.CONNECTING) {
            builder.addAction(R.drawable.ic_vpn_key, "Disconnect", stopIntent)
        }
        return builder.build()
    }
}
