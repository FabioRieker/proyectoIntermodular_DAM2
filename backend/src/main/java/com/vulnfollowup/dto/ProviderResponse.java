package com.vulnfollowup.dto;

import java.time.LocalDate;

import com.vulnfollowup.model.Provider;

public record ProviderResponse(
        String code,
        String name,
        String service,
        String criticality,
        String contractRef,
        LocalDate reviewDate,
        String contact) {

    public static ProviderResponse of(Provider provider) {
        return new ProviderResponse(provider.getCode(), provider.getName(), provider.getService(),
            provider.getCriticality(), provider.getContractRef(), provider.getReviewDate(), provider.getContact());
    }

}
