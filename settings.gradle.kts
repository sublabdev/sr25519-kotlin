rootProject.name = "sr25519-kotlin"
pluginManagement {
    val kotlinVersion: String by settings
    val dokkaVersion: String by settings
    val nexusVersion: String by settings
    plugins {
        kotlin("jvm") version kotlinVersion
        kotlin("plugin.serialization") version kotlinVersion
        id("org.jetbrains.dokka") version dokkaVersion
        id("io.github.gradle-nexus.publish-plugin") version nexusVersion
        `maven-publish`
        signing
    }

    val ossrhToken: String by settings
    val ossrhTokenPassword: String by settings
    extra.set("ossrhToken", ossrhToken)
    extra.set("ossrhTokenPassword", ossrhTokenPassword)
}