package dev.sublab.sr25519

internal fun divideScalarBytesByCofactor(input: ByteArray): ByteArray {
    val scalar = input.copyOf()

    var low: Byte = 0
    for ((i, byte) in scalar.reversed().withIndex()) {
        var b = byte.toUByte().toInt() // convert to UByte initially to keep proper bit shifting
        val r = b and 0b00000111 // save remainder

        b = b shr 3 // divide by 8
        b += low
        scalar[i] = b.toByte()

        low = (r shl 5).toByte()
    }

    return scalar.reversed().toByteArray()
}

internal fun multiplyScalarBytesByCofactor(input: ByteArray): ByteArray {
    val scalar = input.copyOf()

    var high: Byte = 0
    for ((i, byte) in scalar.withIndex()) {
        var b = byte.toUByte().toInt() // convert to UByte initially to keep proper bit shifting
        val r = b and 0b11100000 // carry bits

        b = b shl 3 // multiply by 8
        b += high
        scalar[i] = b.toByte()

        high = (r shr 5).toByte()
    }

    return scalar
}