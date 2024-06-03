import org.jetbrains.kotlin.config.JvmTarget

plugins {
    id("com.github.johnrengelman.shadow") version "8.1.1"
    kotlin("jvm") version "1.9.23"
}

group = "com.zenmo"
version = "0.1"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))

    implementation("com.nimbusds:nimbus-jose-jwt:9.39.2")
    implementation("com.google.crypto.tink:tink:1.13.0")

    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:1.9.23")
}

tasks.test {
//    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}
