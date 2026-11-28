package com.vulnfollowup.controller;

import java.util.List;

import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vulnfollowup.dto.AssetResponse;
import com.vulnfollowup.dto.ProviderResponse;
import com.vulnfollowup.repository.AssetRepository;
import com.vulnfollowup.repository.ProviderRepository;

// Consulta del catálogo de activos y proveedores TIC. Cualquier usuario autenticado.
@RestController
public class CatalogController {

    private final AssetRepository assets;
    private final ProviderRepository providers;

    public CatalogController(AssetRepository assets, ProviderRepository providers) {
        this.assets = assets;
        this.providers = providers;
    }

    @GetMapping("/api/assets")
    public List<AssetResponse> listAssets() {
        return assets.findAllByOrderByCodeAsc().stream()
            .map(AssetResponse::of)
            .toList();
    }

    @GetMapping("/api/providers")
    public List<ProviderResponse> listProviders() {
        return providers.findAll(Sort.by("code")).stream()
            .map(ProviderResponse::of)
            .toList();
    }

}
