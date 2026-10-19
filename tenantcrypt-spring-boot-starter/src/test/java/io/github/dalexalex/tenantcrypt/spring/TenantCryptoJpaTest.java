package io.github.dalexalex.tenantcrypt.spring;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

/** A JPA slice test with the starter auto-configured and development keys in place. */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@DataJpaTest
@ImportAutoConfiguration(TenantCryptoAutoConfiguration.class)
@TestPropertySource(
        properties = {
            "tenantcrypt.master-key=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
            "tenantcrypt.dev-seed=a-development-seed-at-least-32-chars-long",
        })
@interface TenantCryptoJpaTest {}
