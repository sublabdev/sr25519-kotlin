package dev.sublab.merlin

import dev.sublab.common.numerics.toByteArray
import kotlin.random.Random

class TranscriptRngBuilder(private val strobe: Strobe128) {
    @Throws(Exception::class)
    fun rekeyWithWitnessBytes(label: ByteArray, witness: ByteArray) = apply {
        strobe.metaAd(label, false)
        strobe.metaAd(witness.size.toByteArray(), true)
        strobe.key(witness, false)
    }

    @Throws(Exception::class)
    fun finalize() = finalizeWith(Random.Default)

    @Throws(Exception::class)
    fun <R: Random> finalizeWith(random: R): TranscriptRng {
        val randomBytes = random.nextBytes(32)

        strobe.metaAd("rng".toByteArray(), false)
        strobe.key(randomBytes, false)

        return TranscriptRng(strobe.clone())
    }
}