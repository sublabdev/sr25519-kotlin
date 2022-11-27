package dev.sublab.merlin

import dev.sublab.common.numerics.toByteArray

private const val MERLIN_PROTOCOL_LABEL = "Merlin v1.0"

interface Transcript: Cloneable {
    fun appendMessage(label: ByteArray, message: ByteArray)
    fun appendUInt64(label: ByteArray, x: Long)
    fun challengeBytes(label: ByteArray, destination: ByteArray)
    fun buildRng(): TranscriptRngBuilder
}

class TranscriptImpl(private val strobe: Strobe128): Transcript {
    constructor(label: ByteArray): this(Strobe128(MERLIN_PROTOCOL_LABEL.toByteArray())) {
        appendMessage("dom-sep".toByteArray(), label)
    }

    @Throws(Exception::class)
    override fun appendMessage(label: ByteArray, message: ByteArray) {
        strobe.metaAd(label, false)
        strobe.metaAd(message.size.toByteArray(), true)
        strobe.ad(message, false)
    }

    @Throws(Exception::class)
    override fun appendUInt64(label: ByteArray, x: Long) = appendMessage(label, x.toByteArray())

    @Throws(Exception::class)
    override fun challengeBytes(label: ByteArray, destination: ByteArray) {
        strobe.metaAd(label, false)
        strobe.metaAd(destination.size.toByteArray(), true)
        strobe.prf(destination, false)
    }

    override fun buildRng() = TranscriptRngBuilder(strobe.clone())

    public override fun clone() = TranscriptImpl(strobe.clone())
}