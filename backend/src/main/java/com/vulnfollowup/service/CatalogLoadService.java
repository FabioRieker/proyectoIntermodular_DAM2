package com.vulnfollowup.service;

import com.vulnfollowup.model.Asset;
import com.vulnfollowup.model.Provider;
import com.vulnfollowup.model.UserAccount;
import com.vulnfollowup.repository.AssetRepository;
import com.vulnfollowup.repository.ProviderRepository;
import com.vulnfollowup.repository.UserAccountRepository;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.function.Consumer;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@Service
public class CatalogLoadService {
    private final ProviderRepository providers;
    private final AssetRepository assets;
    private final UserAccountRepository accounts;
    private final JsonMapper json = JsonMapper.builder()
        .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
            DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY,
            DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .build();

    public CatalogLoadService(ProviderRepository providers, AssetRepository assets, UserAccountRepository accounts) {
        this.providers = providers;
        this.assets = assets;
        this.accounts = accounts;
    }

    @Transactional
    public void load(Path providersFile, Path assetsFile) {
        loadRows(providersFile, ProviderRow.class, this::saveProvider);
        loadRows(assetsFile, AssetRow.class, this::saveAsset);
    }

    private void saveProvider(ProviderRow row) {
        providers.saveAndFlush(new Provider(row.code(), row.name(), row.service(), row.criticality(),
            row.contractRef(), row.reviewDate(), row.contact()));
    }

    private void saveAsset(AssetRow row) {
        UserAccount owner = accounts.findByEmail(row.ownerEmail())
            .orElseThrow(() -> new IllegalArgumentException("Propietario inexistente: " + row.ownerEmail()));
        Provider provider = null;
        if (row.providerCode() != null) {
            provider = providers.findByCode(row.providerCode())
                .orElseThrow(() -> new IllegalArgumentException("Proveedor inexistente: " + row.providerCode()));
        }
        if (row.active() == null) {
            throw new IllegalArgumentException("Se requiere el campo active.");
        }
        assets.saveAndFlush(new Asset(row.code(), row.name(), row.type(), owner, row.environment(),
            row.active(), provider));
    }

    private <T> void loadRows(Path file, Class<T> rowType, Consumer<T> save) {
        JsonNode rows;
        try {
            rows = json.readTree(file);
        } catch (JacksonException error) {
            throw new IllegalArgumentException("No se pudo leer " + file + ": " + error.getOriginalMessage(), error);
        }
        if (rows == null || !rows.isArray()) {
            throw new IllegalArgumentException(file + " debe contener un array JSON.");
        }

        for (JsonNode row : rows) {
            String code = row.path("code").stringValue(null);
            if (code == null || code.isBlank()) {
                throw new IllegalArgumentException(file + " (sin código): se requiere un código no vacío.");
            }
            try {
                save.accept(json.treeToValue(row, rowType));
            } catch (RuntimeException error) {
                String detail = error.getMessage();
                if (error instanceof DataIntegrityViolationException violation
                    && violation.getMostSpecificCause() instanceof SQLException sql
                    && "23505".equals(sql.getSQLState())) {
                    detail = "Código duplicado.";
                }
                throw new IllegalArgumentException(file + " (" + code + "): " + detail, error);
            }
        }
    }

    private record ProviderRow(String code, String name, String service, String criticality, String contractRef,
                               LocalDate reviewDate, String contact) {
    }

    private record AssetRow(String code, String name, String type, String ownerEmail, String environment,
                            Boolean active, String providerCode) {
    }
}
