description = "Per-tenant envelope encryption with searchable fingerprints — framework-free core"

dependencies {
    api(libs.tink)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj)
    testRuntimeOnly(libs.junit.launcher)
}
