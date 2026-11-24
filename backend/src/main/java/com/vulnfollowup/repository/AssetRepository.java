package com.vulnfollowup.repository;

import com.vulnfollowup.model.Asset;
import java.util.Collection;
import java.util.List;
import org.springframework.data.repository.Repository;

public interface AssetRepository extends Repository<Asset, Long> {
    List<Asset> findAllByCodeIn(Collection<String> codes);
}
