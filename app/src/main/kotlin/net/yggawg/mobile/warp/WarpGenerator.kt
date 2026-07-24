package net.yggawg.mobile.warp

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.spec.NamedParameterSpec
import java.time.Instant
import java.util.concurrent.TimeUnit

/**
 * Генератор Cloudflare WARP-аккаунтов.
 *
 * Логика полностью на устройстве:
 * 1. Генерируем X25519-ключи (приватник не покидает телефон)
 * 2. POST на api.cloudflareclient.com с публичным ключом
 * 3. Парсим ответ: peer pubkey, client v4/v6, client_id
 * 4. Собираем WireGuard .conf
 */
class WarpGenerator(
    private val client: OkHttpClient = DEFAULT_CLIENT,
) {
    companion object {
        private const val TAG = "WarpGenerator"

        private const val API_BASE = "https://api.cloudflareclient.com"
        private const val API_VERSION = "v0a2158"
        private const val CF_CLIENT_VERSION = "a-7.21-0721"
        private const val USER_AGENT = "okhttp/3.12.1"

        private val JSON_MEDIA = "application/json".toMediaType()
        private val JSON = Json { ignoreUnknownKeys = true }

        private val DEFAULT_CLIENT = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()

        /** Версия API, обновлять при несовместимости с wgcf */
        fun apiUrlReg(): String = "$API_BASE/$API_VERSION/reg"
        fun apiUrlAccount(deviceId: String): String = "$API_BASE/$API_VERSION/reg/$deviceId/account"
        fun apiUrlDevice(deviceId: String): String = "$API_BASE/$API_VERSION/reg/$deviceId"
    }

    data class WarpResult(
        val success: Boolean,
        val config: WarpConfig? = null,
        val error: String? = null,
    )

    /**
     * Зарегистрировать новое WARP-устройство.
     * @param licenseKey опциональный WARP+ license key
     * @param endpoint кастомный endpoint (null = дефолтный)
     * @param obfuscate добавить AmneziaWG-обфускацию
     */
    suspend fun register(
        licenseKey: String? = null,
        endpoint: String? = null,
        obfuscate: Boolean = false,
    ): WarpResult = withContext(Dispatchers.IO) {
        try {
            // 1. Генерируем X25519 ключи
            val (privKey, pubKey) = generateX25519KeyPair()

            // 2. Формируем тело запроса
            val now = Instant.now().toString()
            val regBody = JSONObject().apply {
                put("key", pubKey)
                put("install_id", "")
                put("fcm_token", "")
                put("tos", now)
                put("model", "PC")
                put("type", "Android")
                put("locale", "en_US")
            }

            // 3. POST на Cloudflare API
            val request = Request.Builder()
                .url(apiUrlReg())
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .header("CF-Client-Version", CF_CLIENT_VERSION)
                .post(regBody.toString().toRequestBody(JSON_MEDIA))
                .build()

            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: ""

            if (response.code != 200) {
                return@withContext WarpResult(
                    success = false,
                    error = "Registration failed (HTTP ${response.code}). API version may have changed."
                )
            }

            // 4. Парсим ответ
            val config = parseRegistrationResponse(body, privKey, endpoint ?: WarpConfig.DEFAULT_ENDPOINT, now)
                ?: return@withContext WarpResult(success = false, error = "Failed to parse registration response")

            // 5. Если есть license — пробуем активировать WARP+
            var finalConfig = config
            if (!licenseKey.isNullOrBlank()) {
                val licenseResult = applyLicense(config, licenseKey)
                if (licenseResult != null) {
                    finalConfig = licenseResult
                }
            }

            WarpResult(success = true, config = finalConfig)
        } catch (e: Exception) {
            WarpResult(success = false, error = "Network error: ${e.message}")
        }
    }

    /**
     * Генерация X25519 ключей (приватный + публичный в base64).
     * Использует стандартный XDH через java.security (API 26+).
     */
    private fun generateX25519KeyPair(): Pair<String, String> {
        val kpg = KeyPairGenerator.getInstance("XDH")
        kpg.initialize(NamedParameterSpec.X25519)
        val keyPair = kpg.generateKeyPair()

        val privBytes = keyPair.private.encoded
        val pubBytes = keyPair.public.encoded

        // Извлечение raw 32 байт из PKCS8/SPKI
        val rawPriv = extractRawPrivateKey(privBytes)
        val rawPub = extractRawPublicKey(pubBytes)

        val privB64 = Base64.encodeToString(rawPriv, Base64.NO_WRAP)
        val pubB64 = Base64.encodeToString(rawPub, Base64.NO_WRAP)

        return Pair(privB64, pubB64)
    }

    /**
     * Извлекает raw 32 байта приватного ключа из PKCS8 (#0x302e...).
     * Формат PKCS8 для X25519: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.110 },
     *   OCTET STRING { OCTET STRING <32 байта> } }
     * Ищем маркер "04 20" (OCTET STRING длины 32) — первый такой после OID.
     */
    private fun extractRawPrivateKey(pkcs8: ByteArray): ByteArray {
        if (pkcs8.size < 16) return pkcs8
        // Ищем 04 20 (OCTET STRING tag + length 32) после OID (2B 65 6E)
        val oidEnd = pkcs8.indexOf(byteArrayOf(0x2B, 0x65, 0x6E))
        if (oidEnd >= 0) {
            val searchStart = oidEnd + 3
            for (i in searchStart until pkcs8.size - 33) {
                if (pkcs8[i] == 0x04.toByte() && pkcs8[i + 1] == 0x20.toByte()) {
                    return pkcs8.copyOfRange(i + 2, i + 34)
                }
            }
        }
        // Fallback: последние 32 байта
        return pkcs8.copyOfRange(pkcs8.size - 32, pkcs8.size)
    }

    /**
     * Извлекает raw 32 байта публичного ключа из SPKI.
     * Формат SPKI для X25519: SEQUENCE { SEQUENCE { OID 1.3.101.110 },
     *   BIT STRING { 00 <32 байта> } }
     * Ищем маркер "03 21 00" (BIT STRING длины 33 + 0 unused bits).
     */
    private fun extractRawPublicKey(spki: ByteArray): ByteArray {
        if (spki.size < 16) return spki
        // Ищем 03 21 00 (BIT STRING tag + length 33 + 0 unused bits)
        for (i in 0 until spki.size - 35) {
            if (spki[i] == 0x03.toByte() && spki[i + 1] == 0x21.toByte() && spki[i + 2] == 0x00.toByte()) {
                return spki.copyOfRange(i + 3, i + 35)
            }
        }
        // Fallback: последние 32 байта
        return spki.copyOfRange(spki.size - 32, spki.size)
    }

    /** Поиск подмассива [needle] в массиве. */
    private fun ByteArray.indexOf(needle: ByteArray): Int {
        if (needle.isEmpty() || size < needle.size) return -1
        for (i in 0..size - needle.size) {
            var match = true
            for (j in needle.indices) {
                if (this[i + j] != needle[j]) { match = false; break }
            }
            if (match) return i
        }
        return -1
    }

    /**
     * Парсит JSON-ответ от Cloudflare /reg.
     */
    private fun parseRegistrationResponse(
        json: String,
        privKey: String,
        endpoint: String,
        createdAt: String,
    ): WarpConfig? {
        return try {
            val root = JSON.parseToJsonElement(json).jsonObject

            val deviceId = root["id"]?.jsonPrimitive?.content ?: ""
            val token = root["token"]?.jsonPrimitive?.content ?: ""
            val accountObj = root["account"]?.jsonObject
            val accountId = accountObj?.get("id")?.jsonPrimitive?.content ?: ""

            val config = root["config"]?.jsonObject ?: return null
            val clientId = config["client_id"]?.jsonPrimitive?.content ?: ""

            // Interface addresses
            val iface = config["interface"]?.jsonObject
            val v4 = iface?.get("addresses")?.jsonObject?.get("v4")?.jsonPrimitive?.content ?: ""
            val v6 = iface?.get("addresses")?.jsonObject?.get("v6")?.jsonPrimitive?.content ?: ""
            if (v4.isEmpty()) return null

            // Peer
            val peers = config["peers"]?.jsonArray
            val peerPub = if (peers != null && peers.isNotEmpty()) {
                peers[0].jsonObject["public_key"]?.jsonPrimitive?.content ?: ""
            } else ""

            if (peerPub.isEmpty()) return null

            // Endpoint из ответа (если пользовательский не задан)
            var host = endpoint
            if (peers != null && peers.isNotEmpty()) {
                val ep = peers[0].jsonObject["endpoint"]?.jsonObject
                if (ep != null && endpoint == WarpConfig.DEFAULT_ENDPOINT) {
                    val cfHost = ep["host"]?.jsonPrimitive?.content
                    if (!cfHost.isNullOrEmpty()) host = cfHost
                }
            }

            WarpConfig(
                privateKey = privKey,
                peerPublicKey = peerPub,
                clientV4 = v4,
                clientV6 = v6,
                clientId = clientId,
                accountId = accountId,
                deviceId = deviceId,
                token = token,
                endpoint = host,
                createdAt = createdAt,
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Применить WARP+ license key к аккаунту.
     * Возвращает null при ошибке (не фатально — аккаунт остаётся free).
     */
    private suspend fun applyLicense(
        config: WarpConfig,
        license: String,
    ): WarpConfig? {
        if (config.deviceId.isEmpty() || config.token.isEmpty()) return null

        return try {
            val licenseBody = JSONObject().apply {
                put("license", license)
            }

            val request = Request.Builder()
                .url(apiUrlAccount(config.deviceId))
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .header("CF-Client-Version", CF_CLIENT_VERSION)
                .header("Authorization", "Bearer ${config.token}")
                .patch(licenseBody.toString().toRequestBody(JSON_MEDIA))
                .build()

            val response = client.newCall(request).execute()
            if (response.code != 200) {
                return config.copy(license = license)
            }

            val body = response.body?.string() ?: return config.copy(license = license)
            val json = JSON.parseToJsonElement(body).jsonObject

            val warpPlus = json["warp_plus"]?.jsonPrimitive?.content == "true" ||
                json["account"]?.jsonObject?.get("warp_plus")?.jsonPrimitive?.content == "true"

            config.copy(license = license, warpPlus = warpPlus)
        } catch (_: Exception) {
            config.copy(license = license)
        }
    }
}
