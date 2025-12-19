plugins {
    application
    java
}

group = "com.pavel.crypto"
version = "1.0-SNAPSHOT"

application {
    mainClass.set("com.pavel.crypto.Main")
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks.test {
    useJUnitPlatform()
}