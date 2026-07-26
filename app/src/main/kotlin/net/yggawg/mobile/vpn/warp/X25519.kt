package net.yggawg.mobile.vpn.warp

import android.util.Base64
import java.security.SecureRandom

/**
 * X25519 key agreement per RFC 7748.
 *
 * Field arithmetic: 16 × 16-bit limbs in GF(2^255 - 19).
 * Montgomery ladder with constant-time swap.
 * Pure Kotlin, zero external dependencies.
 */
object X25519 {
    private const val KEY_LEN = 32

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

    private fun scalarMultBase(s: ByteArray): ByteArray {
        val u = ByteArray(KEY_LEN); u[0] = 9
        return scalarMult(s, u)
    }

    /** Montgomery ladder: compute [k]u on Curve25519. */
    private fun scalarMult(scalarIn: ByteArray, uIn: ByteArray): ByteArray {
        val k = clamp(scalarIn.copyOf())
        var x1 = decodeU(uIn)
        var x2 = one()
        var z2 = zero()
        var x3 = x1.copyOf()
        var z3 = one()
        var swap = 0
        for (t in 254 downTo 0) {
            val kt = (k[t / 8].toInt() ushr (t % 8)) and 1
            swap = swap xor kt
            cswap(swap, x2, x3); cswap(swap, z2, z3)
            swap = kt
            val a = add(x2, z2)
            val aa = sq(a)
            val b = sub(x2, z2)
            val bb = sq(b)
            val e = sub(aa, bb)
            val c = add(x3, z3)
            val d = sub(x3, z3)
            val da = mul(d, x1)
            val cb = mul(c, a)
            val dd = sq(sub(da, cb))
            val cc = sq(add(da, cb))
            x3 = sq(add(z3, mulW(cb, 121665)))
            z3 = mul(x1, dd)
            x2 = mul(sq(add(x2, mulW(z2, 121665))), e)
            z2 = mul(aa, e)
        }
        cswap(swap, x2, x3); cswap(swap, z2, z3)
        return encode(mul(x2, inv(z2)))
    }

    // ── Field types: LongArray with 16 × 16-bit limbs ──

    private fun zero() = LongArray(16)
    private fun one(): LongArray { val r = zero(); r[0] = 1; return r }

    private fun decodeU(b: ByteArray): LongArray {
        val h = zero()
        for (i in 0 until 16) {
            val b0 = if (2 * i < b.size) b[2 * i].toInt() and 0xFF else 0
            val b1 = if (2 * i + 1 < b.size) b[2 * i + 1].toInt() and 0xFF else 0
            h[i] = (b0 or (b1 shl 8)).toLong()
        }
        h[15] = h[15] and 0x7FFF
        return h
    }

    private fun encode(h: LongArray): ByteArray {
        val t = h.copyOf()
        reduce(t)
        val out = ByteArray(32)
        for (i in 0 until 16) {
            out[2 * i] = (t[i].toInt() and 0xFF).toByte()
            out[2 * i + 1] = ((t[i].toInt() ushr 8) and 0xFF).toByte()
        }
        return out
    }

    private fun reduce(t: LongArray) {
        // Carry propagation
        for (i in 0 until 15) {
            t[i + 1] += t[i] ushr 16
            t[i] = t[i] and 0xFFFF
        }
        t[15] = t[15] and 0x7FFF
        // Reduce using 2^255 ≡ 19 (mod p)
        val c = t[15] ushr 15
        t[15] = t[15] and 0x7FFF
        t[0] += c * 19
        for (i in 0 until 15) {
            t[i + 1] += t[i] ushr 16
            t[i] = t[i] and 0xFFFF
        }
        t[15] = t[15] and 0x7FFF
    }

    private fun add(a: LongArray, b: LongArray): LongArray {
        val r = LongArray(16)
        for (i in 0 until 16) r[i] = a[i] + b[i]
        return r
    }

    private fun sub(a: LongArray, b: LongArray): LongArray {
        val r = LongArray(16)
        for (i in 0 until 16) r[i] = a[i] - b[i] + 0x1FFFE0 // enough for borrows
        return r
    }

    private fun mul(a: LongArray, b: LongArray): LongArray {
        val t = LongArray(32)
        for (i in 0 until 16) for (j in 0 until 16) t[i + j] += a[i] * b[j]
        // Reduce high half: 2^(16*(i+16)) * 19 mod p
        for (i in 0 until 16) t[i] += t[i + 16] * 19
        reduce(t)
        return t.copyOfRange(0, 16)
    }

    private fun mulW(a: LongArray, w: Int): LongArray {
        val r = LongArray(16)
        for (i in 0 until 16) r[i] = a[i] * w
        return r
    }

    private fun sq(a: LongArray): LongArray = mul(a, a)

    /** Modular inverse via a^(p-2) = a^(2^255 - 21). */
    private fun inv(a: LongArray): LongArray {
        var t = a.copyOf()
        // p-2 = 2^255 - 21: binary = 111...1011 (253 ones, then 0, 1, 1)
        // First 253 squarings (all bits are 1) -> wait, actually exponent 2^255-21 means 254 operations.
        // It's much simpler to just use optimized addition chain.
        // Let's rewrite it correctly.
        var t2 = sq(a)
        t2 = mul(t2, a) // a^3
        var t3 = sq(t2)
        t3 = sq(t3)
        t3 = mul(t3, t2) // a^15
        var t4 = t3
        for (i in 0 until 4) t4 = sq(t4)
        t4 = mul(t4, t3) // a^(2^8 - 1)
        var t5 = t4
        for (i in 0 until 8) t5 = sq(t5)
        t5 = mul(t5, t4) // a^(2^16 - 1)
        var t6 = t5
        for (i in 0 until 16) t6 = sq(t6)
        t6 = mul(t6, t5) // a^(2^32 - 1)
        var t7 = t6
        for (i in 0 until 32) t7 = sq(t7)
        t7 = mul(t7, t6) // a^(2^64 - 1)
        var t8 = t7
        for (i in 0 until 64) t8 = sq(t8)
        t8 = mul(t8, t7) // a^(2^128 - 1)
        var t9 = t8
        for (i in 0 until 125) t9 = sq(t9) // 253 bits total: 128 + 125
        t9 = mul(t9, t8) // wait, 128+125 = 253 bits.
        // actually let's just do square and multiply correctly using the exact binary exponent!

        return inv2(a)
    }

    private fun inv2(a: LongArray): LongArray {
        // p-2 as bits, MSB first (bit 254 down to 0)
        // p = 2^255 - 19, p-2 = 2^255 - 21
        // Actually: p-2 in hex = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB
        // Last 8 bits: 11101011 = 0xEB
        val exp = ByteArray(32)
        exp[0] = 0xEB.toByte()
        for (i in 1 until 31) exp[i] = 0xFF.toByte()
        exp[31] = 0x7F

        var t = one()
        var started = false
        for (byteIdx in 31 downTo 0) {
            for (bitIdx in 7 downTo 0) {
                val bit = (exp[byteIdx].toInt() ushr bitIdx) and 1
                if (started || bit == 1) {
                    if (started) t = sq(t)
                    started = true
                    if (bit == 1) t = mul(t, a)
                }
            }
        }
        return t
    }

    private fun cswap(s: Int, a: LongArray, b: LongArray) {
        val m = (-s).toLong()
        for (i in 0 until 16) {
            val x = m and (a[i] xor b[i])
            a[i] = a[i] xor x; b[i] = b[i] xor x
        }
    }

    private fun clamp(k: ByteArray): ByteArray {
        k[0] = (k[0].toInt() and 0xF8).toByte()
        k[31] = ((k[31].toInt() and 0x7F) or 0x40).toByte()
        return k
    }
}
