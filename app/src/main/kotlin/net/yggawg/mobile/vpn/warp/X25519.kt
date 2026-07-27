package net.yggawg.mobile.vpn.warp

import android.util.Base64
import java.math.BigInteger
import java.security.SecureRandom

/**
 * X25519 key agreement per RFC 7748.
 *
 * Implemented using `java.math.BigInteger` for 100% correct
 * mathematical operations over GF(2^255 - 19) safely.
 */
object X25519 {
    private const val KEY_LEN = 32
    private val P = BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16) // 2^255 - 19
    private val A24 = BigInteger.valueOf(121665)

    data class KeyPair(val privateBase64: String, val publicBase64: String)

    fun generateKeyPair(): KeyPair {
        val priv = ByteArray(KEY_LEN)
        SecureRandom().nextBytes(priv)
        priv[0] = (priv[0].toInt() and 0xF8).toByte()
        priv[31] = ((priv[31].toInt() and 0x7F) or 0x40).toByte()
        val pub = scalarMultBase(priv)
        return KeyPair(
            Base64.encodeToString(priv, Base64.NO_WRAP),
            Base64.encodeToString(pub, Base64.NO_WRAP),
        )
    }

    private fun scalarMultBase(scalarIn: ByteArray): ByteArray {
        val u = ByteArray(KEY_LEN)
        u[0] = 9
        return scalarMult(scalarIn, u)
    }

    private fun scalarMult(scalarIn: ByteArray, uIn: ByteArray): ByteArray {
        val k = scalarIn.copyOf()
        k[0] = (k[0].toInt() and 0xF8).toByte()
        k[31] = ((k[31].toInt() and 0x7F) or 0x40).toByte()

        val x1 = decodeLittleEndian(uIn)
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE

        var swap = 0
        for (t in 254 downTo 0) {
            val kt = (k[t / 8].toInt() ushr (t % 8)) and 1
            swap = swap xor kt
            if (swap == 1) {
                var tmp = x2; x2 = x3; x3 = tmp
                tmp = z2; z2 = z3; z3 = tmp
            }
            swap = kt

            val a = x2.add(z2).mod(P)
            val aa = a.pow(2).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.pow(2).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)

            val dPlusC = da.add(cb).mod(P)
            val dMinusC = da.subtract(cb).mod(P)

            x3 = dPlusC.pow(2).mod(P)
            z3 = x1.multiply(dMinusC.pow(2).mod(P)).mod(P)

            x2 = aa.multiply(bb).mod(P)
            val eA24 = e.multiply(A24).mod(P)
            z2 = e.multiply(aa.add(eA24).mod(P)).mod(P)
        }
        if (swap == 1) {
            var tmp = x2; x2 = x3; x3 = tmp
            tmp = z2; z2 = z3; z3 = tmp
        }

        val invZ2 = z2.modInverse(P)
        val res = x2.multiply(invZ2).mod(P)
        return encodeLittleEndian(res)
    }

    private fun decodeLittleEndian(b: ByteArray): BigInteger {
        val bytes = b.copyOf()
        bytes[31] = (bytes[31].toInt() and 0x7F).toByte()
        bytes.reverse() // little endian to big endian
        return BigInteger(1, bytes)
    }

    private fun encodeLittleEndian(num: BigInteger): ByteArray {
        val out = ByteArray(32)
        val b = num.toByteArray() // returns big endian
        var j = 0
        // Fill from the end of the BigInteger's byte array (least significant bytes)
        for (i in b.size - 1 downTo 0) {
            if (j >= 32) break
            out[j++] = b[i]
        }
        // Leftover bytes are inherently 0.
        return out
    }
}
