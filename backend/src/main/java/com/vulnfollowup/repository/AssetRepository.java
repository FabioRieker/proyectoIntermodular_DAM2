package com.vulnfollowup.repository;

import com.vulnfollowup.model.Asset;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AssetRepository extends JpaRepository<Asset, Long> {
    List<Asset> findAllByCodeIn(Collection<String> codes);
}
