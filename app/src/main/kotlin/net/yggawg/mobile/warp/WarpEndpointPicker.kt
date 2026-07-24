package net.yggawg.mobile.warp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.security.SecureRandom

/**
 * Парсинг warp_endpoints.json и выбор случайных endpoint'ов.
 *
 * Логика из LxBox: Monte-Carlo генерация кандидатов {IP × port × SNI}
 * для обхода блокировок Cloudflare WARP.
 */
class WarpEndpointPicker(
    private val endpoints: WarpEndpoints = WarpEndpoints(),
) {
    private val rng = SecureRandom()

    /**
     * Сгенерировать случайный endpoint вида "ip:port" из WG CIDR-блоков.
     * @return строка "ip:port" или null
     */
    fun randomEndpoint(): String? {
        val cidrs = endpoints.wireguard.v4_cidr
        val ports = endpoints.wireguard.ports
        if (cidrs.isEmpty() || ports.isEmpty()) return null

        val cidr = cidrs[rng.nextInt(cidrs.size)]
        val ip = randomIpInCidr(cidr) ?: return null
        val port = ports[rng.nextInt(ports.size)]
        return "$ip:$port"
    }

    /**
     * Сгенерировать случайный SNI из пула WG.
     */
    fun randomSni(): String {
        val pool = endpoints.wireguard.sni_pool
        return if (pool.isNotEmpty()) pool[rng.nextInt(pool.size)]
        else "www.google.com"
    }

    /**
     * Генерирует случайный IP-адрес внутри CIDR.
     * Поддерживает IPv4 CIDR вида "162.159.192.0/24".
     */
    private fun randomIpInCidr(cidr: String): String? {
        try {
            val (baseStr, prefixLenStr) = cidr.split("/")
            val prefixLen = prefixLenStr.toInt()

            val octets = baseStr.split(".").map { it.toInt() and 0xFF }
            if (octets.size != 4) return null

            val ipInt = (octets[0] shl 24) or (octets[1] shl 16) or (octets[2] shl 8) or octets[3]
            val mask = if (prefixLen == 0) 0 else -1 shl (32 - prefixLen)
            val network = ipInt and mask
            val hostBits = 32 - prefixLen

            // Не генерируем сетевой (0) и широковещательный (все единицы) адреса
            val hostMax = (1L shl hostBits) - 1
            val randomHost = if (hostMax > 1) {
                (rng.nextLong() and Long.MAX_VALUE) % hostMax
            } else 0L

            val resultInt = (network.toLong() and 0xFFFFFFFFL) or randomHost
            return "${(resultInt shr 24) and 0xFF}.${(resultInt shr 16) and 0xFF}.${(resultInt shr 8) and 0xFF}.${resultInt and 0xFF}"
        } catch (_: Exception) {
            return null
        }
    }
}
