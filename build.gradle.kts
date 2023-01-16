import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    `maven-publish`
    id("org.jetbrains.dokka")
}

group = "dev.sublab"
version = "1.0.0"

repositories {
    mavenLocal()
    mavenCentral()
    maven { url = uri("https://repo.repsy.io/mvn/chrynan/public") } // Kotlin SecureRandom
}

val dokkaVersion: String by project
val commonVersion: String by project
val hashingVersion: String by project
val curve25519Version: String by project
val kryptVersion: String by project

dependencies {
    testImplementation(kotlin("test"))
    dokkaHtmlPlugin("org.jetbrains.dokka:kotlin-as-java-plugin:$dokkaVersion")
    implementation("dev.sublab:common-kotlin:$commonVersion")
    implementation("dev.sublab:hashing-kotlin:$hashingVersion")
    implementation("dev.sublab:curve25519-kotlin:$curve25519Version")
    implementation("com.chrynan.krypt:krypt-csprng:$kryptVersion")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            artifact(sourcesJar.get())
        }
    }
}