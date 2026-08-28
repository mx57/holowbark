package net.yggawg.mobile.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AwgConfigTest {

    @Test
    fun testParseAwgConf() {
        val confText = """
            [Interface]
            PrivateKey = cGEyM2Q0ZTVmNmc3aDhpOWowazFsMm0zbjRvNXA2cTc=
            Address = 10.0.0.2/32, fd00::2/128
            Jc = 4
            Jmin = 40
            Jmax = 70
            H1 = 1

            [Peer]
            PublicKey = cGEyM2Q0ZTVmNmc3aDhpOWowazFsMm0zbjRvNXA2cTc=
            Endpoint = 127.0.0.1:8886
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()

        val config = parseAwgConf(confText)
        assertNotNull(config)
        assertEquals("cGEyM2Q0ZTVmNmc3aDhpOWowazFsMm0zbjRvNXA2cTc=", config.privateKey)
        assertEquals("10.0.0.2/32, fd00::2/128", config.address)
        assertEquals(4, config.jc)
        assertEquals(40, config.jmin)
        assertEquals(70, config.jmax)
        assertEquals("1", config.h1)
        assertTrue(config.isAwg)
        assertEquals("127.0.0.1:8886", config.endpoint)
    }

    @Test
    fun testResolveEndpointNumericIP() {
        val endpointIPv4 = "192.168.1.1:8886"
        assertEquals("192.168.1.1:8886", resolveEndpoint(endpointIPv4))

        val endpointIPv6 = "[2001:db8::1]:8886"
        assertEquals("[2001:db8::1]:8886", resolveEndpoint(endpointIPv6))
    }

    @Test
    fun testResolveEndpointLocalhost() {
        val endpoint = "localhost:8886"
        val resolved = resolveEndpoint(endpoint)
        assertTrue(resolved == "127.0.0.1:8886" || resolved == "[::1]:8886")
    }
}
