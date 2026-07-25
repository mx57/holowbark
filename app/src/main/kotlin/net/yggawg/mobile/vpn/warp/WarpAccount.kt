package net.yggawg.mobile.vpn.warp

import android.util.Base64
import org.json.JSONObject

/**
 * Cached Cloudflare WARP account.
 *
 * Private key is generated on device and never leaves it — only the public
 * part is sent to Cloudflare during registration.
 */
data class WarpAccount(
    val privKey: String,          // base64 X25519 private key
    val peerPub: String,          // base64 public key of CF peer
    val clientV4: String,         // e.g. "172.16.0.2"
    val clientV6: String,         // e.g. "fd01::2"
    val clientId: String,         // base64 → reserved bytes
    val accountId: String,
    val deviceId: String,
    val token: String,
    val endpoint: String = DEFAULT_ENDPOINT,
    val warpPlus: Boolean = false,
    val license: String? = null,
    val createdAt: String = "",
) {
    /** WireGuard "reserved" as comma-separated decimals (b0,b1,b2). */
    val reserved: String?
        get() {
            if (clientId.isBlank()) return null
            return try {
                val bytes = Base64.decode(clientId, Base64.DEFAULT)
                if (bytes.size >= 3) "${bytes[0]},${bytes[1]},${bytes[2]}" else null
            } catch (_: Exception) { null }
        }

    /** Build a wireguard:// URI for import into any WireGuard client. */
    fun toWireguardUri(tag: String = nodeTag()): String {
        val addrs = buildString {
            append(clientV4)
            if (clientV6.isNotEmpty()) append(",$clientV6")
        }
        val params = mutableListOf(
            "publickey=${urlEncode(peerPub)}",
            "address=${urlEncode(addrs)}",
            "allowedips=0.0.0.0/0,::/0",
            "mtu=1280",
        )
        reserved?.let { params.add("reserved=${urlEncode(it)}") }

        val query = params.joinToString("&")
        return "wireguard://${urlEncode(privKey)}@$endpoint?$query#${urlEncode(tag)}"
    }

    /** Build a WireGuard .conf file (INI format). */
    fun toConfString(tag: String = nodeTag()): String = buildString {
        appendLine("# $tag")
        appendLine("[Interface]")
        appendLine("PrivateKey = $privKey")
        val addrs = if (clientV6.isNotEmpty()) "$clientV4, $clientV6" else clientV4
        appendLine("Address = $addrs")
        appendLine("MTU = 1280")
        appendLine()
        appendLine("[Peer]")
        appendLine("PublicKey = $peerPub")
        appendLine("AllowedIPs = 0.0.0.0/0, ::/0")
        appendLine("Endpoint = $endpoint")
        reserved?.let { appendLine("PersistentKeepalive = 25") }
    }

    fun nodeTag(): String = if (warpPlus) "🔥☁️ WARP+" else "🔥☁️ WARP"

    fun toJson(): JSONObject = JSONObject().apply {
        put("priv_key", privKey)
        put("peer_pub", peerPub)
        put("client_v4", clientV4)
        put("client_v6", clientV6)
        put("client_id", clientId)
        put("account_id", accountId)
        put("device_id", deviceId)
        put("token", token)
        put("endpoint", endpoint)
        put("warp_plus", warpPlus)
        put("license", license ?: "")
        put("created_at", createdAt)
    }

    fun redacted(): Map<String, Any?> = mapOf(
        "peer_pub" to peerPub,
        "client_v4" to clientV4,
        "client_v6" to clientV6,
        "device_id" to deviceId,
        "endpoint" to endpoint,
        "warp_plus" to warpPlus,
        "priv_key" to "<redacted>",
        "token" to "<redacted>",
    )

    companion object {
        const val DEFAULT_ENDPOINT = "engage.cloudflareclient.com:2408"

        fun fromJson(json: JSONObject): WarpAccount? {
            val priv = json.optString("priv_key", "")
            val pub = json.optString("peer_pub", "")
            if (priv.isEmpty() || pub.isEmpty()) return null
            return WarpAccount(
                privKey = priv,
                peerPub = pub,
                clientV4 = json.optString("client_v4", ""),
                clientV6 = json.optString("client_v6", ""),
                clientId = json.optString("client_id", ""),
                accountId = json.optString("account_id", ""),
                deviceId = json.optString("device_id", ""),
                token = json.optString("token", ""),
                endpoint = json.optString("endpoint", DEFAULT_ENDPOINT),
                warpPlus = json.optBoolean("warp_plus", false),
                license = json.optString("license", "").ifBlank { null },
                createdAt = json.optString("created_at", ""),
            )
        }
    }
}

private fun urlEncode(s: String): String =
    java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
