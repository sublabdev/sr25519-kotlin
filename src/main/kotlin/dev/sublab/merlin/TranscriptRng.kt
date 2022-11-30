package dev.sublab.merlin

import dev.sublab.common.numerics.toByteArray
import kotlin.random.Random

class TranscriptRng(private val strobe: Strobe128) {
    fun <R: Random> nextUInt32(random: R) = random.nextInt()
    fun <R: Random> nextUInt64(random: R) = random.nextLong()

    @Throws(Exception::class)
    fun fillBytes(destination: ByteArray) {
        val destinationSize = destination.size.toByteArray()
        strobe.metaAd(destinationSize, false)
        strobe.prf(destination, false)
    }
}