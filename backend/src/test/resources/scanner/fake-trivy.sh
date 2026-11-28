#!/bin/sh
# Sustituto de "trivy fs --format json" para los tests: ignora los argumentos
# y devuelve un informe con el mismo formato.
cat <<'EOF'
{
  "SchemaVersion": 2,
  "Results": [
    {
      "Target": "package-lock.json",
      "Vulnerabilities": [
        { "VulnerabilityID": "CVE-2024-0001", "Severity": "CRITICAL" },
        { "VulnerabilityID": "CVE-2024-0002", "Severity": "HIGH" }
      ]
    },
    { "Target": "pom.xml", "Vulnerabilities": null }
  ]
}
EOF
