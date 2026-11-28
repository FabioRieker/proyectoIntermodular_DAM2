package com.vulnfollowup.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDate;

@Entity
@Table(name = "providers")
public class Provider {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 40)
    private String code;

    @Column(nullable = false, columnDefinition = "text")
    private String name;

    @Column(nullable = false, columnDefinition = "text")
    private String service;

    @Column(nullable = false, length = 8)
    private String criticality;

    @Column(name = "contract_ref", nullable = false, columnDefinition = "text")
    private String contractRef;

    @Column(name = "review_date", nullable = false)
    private LocalDate reviewDate;

    @Column(nullable = false, columnDefinition = "text")
    private String contact;

    protected Provider() {
    }

    public Provider(String code, String name, String service, String criticality, String contractRef,
                    LocalDate reviewDate, String contact) {
        this.code = code;
        this.name = name;
        this.service = service;
        this.criticality = criticality;
        this.contractRef = contractRef;
        this.reviewDate = reviewDate;
        this.contact = contact;
    }
}
