description = "Optional Spring Boot integration: ambient tenant context and JPA converters"

dependencies {
    api(project(":tenantcrypt-core"))

    // compileOnly, not api: this module is optional and must not drag Spring into the classpath of
    // anyone who only wants the core. Consumers already have these.
    //
    // Note what is deliberately absent: Hibernate, and even spring-data-jpa. Main sources compile
    // against the JPA *specification* only, so this module works on any JPA provider — and
    // reintroducing a provider-specific import is a compile error rather than a review comment.
    // See ADR 0008.
    compileOnly(libs.spring.boot.autoconfigure)
    compileOnly(libs.jakarta.persistence)

    testImplementation(libs.spring.boot.autoconfigure)
    testImplementation(libs.spring.boot.data.jpa)
    testImplementation(libs.spring.boot.test)
    testRuntimeOnly(libs.h2)
    testImplementation(libs.assertj)
    testRuntimeOnly(libs.junit.launcher)
}
