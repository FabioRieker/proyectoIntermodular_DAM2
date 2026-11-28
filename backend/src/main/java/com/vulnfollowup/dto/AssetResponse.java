package com.vulnfollowup.dto;

import com.vulnfollowup.model.Asset;

public record AssetResponse(
        String code,
        String name,
        String type,
        String environment,
        boolean active,
        String ownerEmail,
        String providerCode) {

    public static AssetResponse of(Asset asset) {
        String providerCode = asset.getProvider() == null ? null : asset.getProvider().getCode();
        return new AssetResponse(asset.getCode(), asset.getName(), asset.getType(), asset.getEnvironment(),
            asset.isActive(), asset.getOwner().getEmail(), providerCode);
    }

}
