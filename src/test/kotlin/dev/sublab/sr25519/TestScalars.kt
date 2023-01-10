package dev.sublab.sr25519

import com.chrynan.krypt.csprng.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals

private fun debug_divideScalarBytesByCofactor(input: ByteArray): ByteArray {
    val scalar = input.copyOf()

    var low: Byte = 0
    for ((i, byte) in scalar.reversed().withIndex()) {
        var b = byte.toUByte().toInt()
        val r = b and 0b00000111 // save remainder
//        println("[divide][i=$i][0] scalar[i]=${b.toUByte()}, r=${r.toUByte()}")

        b = b shr 3 // divide by 8
//        println("[divide][i=$i][1] scalar[i]=${b.toUByte()}")
        b += low
//        println("[divide][i=$i][2] scalar[i]=${b.toUByte()}")
        scalar[i] = b.toByte()

        low = (r shl 5).toByte()
//        println("[divide][i=$i][3] low=${low.toUByte()}")
    }

    return scalar.reversed().toByteArray()
}

private fun debug_multiplyScalarBytesByCofactor(input: ByteArray): ByteArray {
    val scalar = input.copyOf()

    var high: Byte = 0
    for ((i, byte) in scalar.withIndex()) {
        var b = byte.toUByte().toInt()
        val r = b and 0b11100000 // carry bits
//        println("[multi][i=$i][0] scalar[i]=${b.toUByte()}, r=${r.toUByte()}")

        b = b shl 3 // multiply by 8
//        println("[multi][i=$i][1] scalar[i]=${b.toUByte()}")
        b += high
//        println("[multi][i=$i][2] scalar[i]=${b.toUByte()}")
        scalar[i] = b.toByte()

        high = (r shr 5).toByte()
//        println("[multi][i=$i][3] high=${high.toUByte()}")
    }

    return scalar
}

class TestScalars {
//    @Test
//    fun testRust1() {
//        val x = byteArrayOf(25, -66, 69, -91, -14, -75, 27, 126, 41, -97, 119, 120, -97, -79, -76, -125, 0, 111, -61, -118, -11, 70, -36, 112, 34, -16, 118, -115, -121, -94, -108, 11)
//        x[31] = (x[31].toInt() and 0b00011111).toByte()
//        val y = debug_divideScalarBytesByCofactor(debug_multiplyScalarBytesByCofactor(x))
//        assertContentEquals(x, y)
//    }
//
//    @Test
//    fun testRust2() {
//        val x = byteArrayOf(-29, -10, -45, -29, 63, 111, 57, -99, -128, 3, 44, 42, -36, -115, 105, -77, -2, -94, -86, 24, -112, -47, -12, -102, 99, -14, 43, -93, -75, 94, -127, -64)
//        x[0] = (x[31].toInt() and 0b00011111).toByte()
//        val y = debug_multiplyScalarBytesByCofactor(debug_divideScalarBytesByCofactor(x))
//        assertContentEquals(x, y)
//    }

    @Test
    fun cofactorAdjustment() {
        run {
            val x = SecureRandom().nextBytes(Constants.SCALAR_SIZE)
            x[31] = (x[31].toInt() and 0b00011111).toByte()
            val y = divideScalarBytesByCofactor(multiplyScalarBytesByCofactor(x))
            assertContentEquals(x, y)
        }

        run {
            val x = SecureRandom().nextBytes(Constants.SCALAR_SIZE)
            x[0] = (x[31].toInt() and 0b11111000).toByte()
            val y = multiplyScalarBytesByCofactor(divideScalarBytesByCofactor(x))
            assertContentEquals(x, y)
        }
    }
}