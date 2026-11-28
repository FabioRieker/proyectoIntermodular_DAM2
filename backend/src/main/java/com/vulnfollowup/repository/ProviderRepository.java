package com.vulnfollowup.repository;

import com.vulnfollowup.model.Provider;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProviderRepository extends JpaRepository<Provider, Long> {
    Optional<Provider> findByCode(String code);
}
