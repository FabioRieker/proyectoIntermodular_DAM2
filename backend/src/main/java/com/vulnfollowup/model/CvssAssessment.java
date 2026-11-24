package com.vulnfollowup.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.Instant;

@Entity
@Table(name = "cvss_assessments")
public class CvssAssessment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "vulnerability_id", nullable = false)
    private Vulnerability vulnerability;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "assessor_id", nullable = false)
    private UserAccount assessor;

    @Column(name = "cvss_version", nullable = false, length = 3)
    private String cvssVersion;

    @Column(nullable = false, columnDefinition = "text")
    private String vector;

    @Column(name = "base_score", nullable = false)
    private BigDecimal baseScore;

    @Column(insertable = false, updatable = false, length = 8)
    private String severity;

    @Column(name = "assessed_at", insertable = false, updatable = false)
    private Instant assessedAt;

    protected CvssAssessment() {
    }

    CvssAssessment(Vulnerability vulnerability, UserAccount assessor, String cvssVersion,
                   String vector, BigDecimal baseScore) {
        this.vulnerability = vulnerability;
        this.assessor = assessor;
        this.cvssVersion = cvssVersion;
        this.vector = vector;
        this.baseScore = baseScore;
    }

    public String getAssessorEmail() {
        return assessor.getEmail();
    }

    public String getCvssVersion() {
        return cvssVersion;
    }

    public String getVector() {
        return vector;
    }

    public BigDecimal getBaseScore() {
        return baseScore;
    }

    public String getSeverity() {
        return severity;
    }

    public Instant getAssessedAt() {
        return assessedAt;
    }
}
