rootProject.name = "sr25519-kotlin"
pluginManagement {
    val kotlinVersion: String by settings
    val dokkaVersion: String by settings
    plugins {
        kotlin("jvm") version kotlinVersion
        kotlin("plugin.serialization") version kotlinVersion
        `maven-publish`
        id("org.jetbrains.dokka") version dokkaVersion
    }
}