package com.vulnfollowup.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "assets")
public class Asset {
    @Id
    private Long id;

    @Column(nullable = false, unique = true, length = 40)
    private String code;

    protected Asset() {
    }

    public String getCode() {
        return code;
    }
}
