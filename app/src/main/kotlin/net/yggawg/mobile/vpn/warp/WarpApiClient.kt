package net.yggawg.mobile.vpn.warp

import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

/**
 * Client for Cloudflare WARP registration API.
 *
 * Generates X25519 keypair locally using pure Kotlin, sends only the public
 * key to Cloudflare. Same protocol as wgcf / official WARP client.
 */
class WarpApiClient(
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build(),
) {
    companion object {
        private const val TAG = "WarpApiClient"
        private const val API_BASE = "https://api.cloudflareclient.com"
        private const val API_VERSION = "v0a2158"
        private const val CLIENT_VERSION = "a-7.21-0721"
        private const val USER_AGENT = "okhttp/3.12.1"
        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
    }

    class WarpException(message: String) : Exception(message)

    /**
     * Register a new WARP device with Cloudflare.
     *
     * @param licenseKey Optional WARP+ license key.
     * @return WarpAccount with all registration data.
     */
    suspend fun register(licenseKey: String? = null): WarpAccount =
        withContext(Dispatchers.IO) {
            val keyPair = X25519.generateKeyPair()
            val nowIso = nowIso8601()

            val body = JSONObject().apply {
                put("key", keyPair.publicBase64)
                put("install_id", "")
                put("fcm_token", "")
                put("tos", nowIso)
                put("model", "PC")
                put("type", "Android")
                put("locale", "en_US")
            }

            val request = Request.Builder()
                .url("$API_BASE/$API_VERSION/reg")
                .post(body.toString().toRequestBody(JSON_MEDIA))
                .header("Content-Type", "application/json")
                .header("User-Agent", USER_AGENT)
                .header("CF-Client-Version", CLIENT_VERSION)
                .build()

            val response = try {
                client.newCall(request).execute()
            } catch (e: Exception) {
                throw WarpException("Network error: ${e.message}")
            }

            if (response.code != 200) {
                throw WarpException(
                    "Registration failed (HTTP ${response.code}). " +
                    "API version may have changed ($API_VERSION)."
                )
            }

            val responseBody = response.body?.string()
                ?: throw WarpException("Empty response body")
            val json = try {
                JSONObject(responseBody)
            } catch (_: Exception) {
                throw WarpException("Bad response: not JSON")
            }

            var account = parseRegistration(json, keyPair.privateBase64)
            Log.i(TAG, "WARP registered: ${account.redacted()}")

            if (!licenseKey.isNullOrBlank()) {
                account = applyLicense(account, licenseKey.trim())
            }
            account
        }

    private fun applyLicense(account: WarpAccount, license: String): WarpAccount {
        if (account.deviceId.isEmpty() || account.token.isEmpty()) {
            Log.w(TAG, "Cannot apply license — no device id/token")
            return account.copy(license = license)
        }
        val body = JSONObject().apply { put("license", license) }
        val request = Request.Builder()
            .url("$API_BASE/$API_VERSION/reg/${account.deviceId}/account")
            .patch(body.toString().toRequestBody(JSON_MEDIA))
            .header("Content-Type", "application/json")
            .header("User-Agent", USER_AGENT)
            .header("CF-Client-Version", CLIENT_VERSION)
            .header("Authorization", "Bearer ${account.token}")
            .build()
        return try {
            val resp = client.newCall(request).execute()
            if (resp.code != 200) {
                Log.w(TAG, "License not applied (HTTP ${resp.code})")
                return account.copy(license = license)
            }
            val json = JSONObject(resp.body?.string() ?: "{}")
            val warpPlus = json.optBoolean("warp_plus", false) ||
                json.optJSONObject("account")
                    ?.optBoolean("warp_plus", false) ?: false
            Log.i(TAG, "WARP+ license applied: warpPlus=$warpPlus")
            account.copy(license = license, warpPlus = warpPlus)
        } catch (e: Exception) {
            Log.w(TAG, "License apply failed: $e")
            account.copy(license = license)
        }
    }

    private fun parseRegistration(
        json: JSONObject,
        privateKeyBase64: String,
    ): WarpAccount {
        val deviceId = json.optString("id", "")
        val token = json.optString("token", "")
        val config = json.optJSONObject("config")
            ?: throw WarpException("Bad response: missing config")
        val clientId = config.optString("client_id", "")
        val peers = config.optJSONArray("peers")
        val peerPub = peers?.optJSONObject(0)
            ?.optString("public_key", "")
            ?: throw WarpException("Bad response: missing peer public_key")
        val host = peers?.optJSONObject(0)
            ?.optJSONObject("endpoint")
            ?.optString("host", WarpAccount.DEFAULT_ENDPOINT)
            ?: WarpAccount.DEFAULT_ENDPOINT
        val iface = config.optJSONObject("interface")
        val addrs = iface?.optJSONObject("addresses")
        val v4 = addrs?.optString("v4", "") ?: ""
        val v6 = addrs?.optString("v6", "") ?: ""
        if (v4.isEmpty()) {
            throw WarpException("Bad response: missing interface address")
        }
        return WarpAccount(
            privKey = privateKeyBase64,
            peerPub = peerPub,
            clientV4 = v4,
            clientV6 = v6,
            clientId = clientId,
            accountId = config.optJSONObject("account")
                ?.optString("id", "") ?: "",
            deviceId = deviceId,
            token = token,
            endpoint = host,
            createdAt = nowIso8601(),
        )
    }

    private data class KeyPair(
        val privateBase64: String,
        val publicBase64: String,
    )

    private fun nowIso8601(): String {
        val fmt = SimpleDateFormat(
            "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US
        )
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date())
    }
}
