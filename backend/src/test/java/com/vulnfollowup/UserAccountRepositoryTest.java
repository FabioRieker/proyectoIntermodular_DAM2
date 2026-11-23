package com.vulnfollowup;

import com.vulnfollowup.model.UserAccount;
import com.vulnfollowup.repository.UserAccountRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class UserAccountRepositoryTest {
    @Autowired
    private UserAccountRepository accounts;

    @Test
    void leeLaCuentaDeAnalisisDesdePostgres() {
        UserAccount account = accounts.findByEmail("analyst@vulnfollowup.local").orElseThrow();
        assertTrue(account.isEnabled());
        assertEquals("ANALYST", account.getRole());
        assertTrue(account.getPasswordHash().startsWith("$2a$"));
    }
}
