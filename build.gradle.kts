plugins {
    `java-library`
    `maven-publish`
}

// Applied to every published module. Core deliberately has no framework dependency (ADR 0002).
subprojects {
    apply(plugin = "java-library")
    apply(plugin = "maven-publish")

    group = "io.github.dalex-alex"
    version = "0.1.0-SNAPSHOT"

    repositories { mavenCentral() }

    extensions.configure<JavaPluginExtension> {
        toolchain { languageVersion = JavaLanguageVersion.of(21) }
        withSourcesJar()
        withJavadocJar()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }

    tasks.withType<Javadoc>().configureEach {
        // Keep the checks that catch real defects — broken {@link} targets, malformed HTML — and
        // fail on them. The "missing" group is switched off deliberately: this library documents
        // intent in prose, and requiring an @param on every argument would bury that in boilerplate.
        (options as StandardJavadocDocletOptions).apply {
            addStringOption("Xdoclint:all,-missing", "-quiet")
            addBooleanOption("Werror", true)
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        testLogging { events("failed", "skipped") }
    }

    // Maven Central requires name, description, url, licence, developer and SCM metadata on
    // every published POM, so it is set here rather than discovered at release time.
    extensions.configure<PublishingExtension> {
        publications {
            create<MavenPublication>("maven") {
                from(components["java"])
                pom {
                    name = this@subprojects.name
                    description = provider { this@subprojects.description }
                    url = "https://github.com/dalex-alex/tenantcrypt"
                    licenses {
                        license {
                            name = "Apache License, Version 2.0"
                            url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                        }
                    }
                    developers {
                        developer {
                            id = "dalex-alex"
                            name = "Alexandru Dragomir"
                        }
                    }
                    scm {
                        url = "https://github.com/dalex-alex/tenantcrypt"
                        connection = "scm:git:https://github.com/dalex-alex/tenantcrypt.git"
                        developerConnection = "scm:git:ssh://git@github.com/dalex-alex/tenantcrypt.git"
                    }
                }
            }
        }
    }
}
