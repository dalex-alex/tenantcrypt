package io.github.dalexalex.tenantcrypt.spring;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/** Minimal boot configuration so the slice tests have a context to start. */
@SpringBootConfiguration
@EnableJpaRepositories
@EntityScan
class TestApplication {}
