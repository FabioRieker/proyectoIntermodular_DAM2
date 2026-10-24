# VulnFollowUp
![Curso](https://img.shields.io/badge/CFGS_2.º_DAM-Instituto_Nebrija-000000?style=for-the-badge)
[![CI/CD Pipeline](https://github.com/FabioRieker/proyectoIntermodular_DAM2/actions/workflows/ci.yml/badge.svg)](https://github.com/FabioRieker/proyectoIntermodular_DAM2/actions)

**Plataforma de gestión de activos, priorización de vulnerabilidades bajo el estándar CVSS (v3.1 / v4.0) y control de riesgo de proveedores TIC alineada con la normativa europea DORA.**

Desarrollada como Proyecto Intermodular de 2.º CFGS en Desarrollo de Aplicaciones Multiplataforma (DAM) en el Instituto Nebrija de Formación Profesional. El sistema proporciona trazabilidad defensiva, ejecución concurrente de auditorías de dependencias en segundo plano y acceso multiplataforma (SPA Web y Android).


---

### Enfoque de Ingeniería y Arquitectura

- **Seguridad y Concurrencia en Backend (PSP):** Autenticación basada en tokens JWT con hash salado de contraseñas, control de acceso basado en roles (RBAC), ejecución de tareas en segundo plano mediante `ExecutorService`, control de condiciones de carrera sobre recursos compartidos e invocación de procesos del sistema con `ProcessBuilder`.
- **Persistencia Transaccional y Resiliencia DORA (AD + SGE):** Modelo relacional normalizado en PostgreSQL con relación N:M entre activos y vulnerabilidades, histórico de reevaluaciones CVSS, importador JSON transaccional con *rollback* automático y motor de reglas de negocio para marcar proveedores TIC en riesgo.
- **Clientes Multiplataforma y Accesibilidad (DI + PMDM):** Arquitectura modular en Ionic + Angular cumpliendo pautas WCAG 2.1 AA, cuadro de mando analítico con exportación a PDF/CSV y aplicación Android con caché local para funcionamiento sin conexión.

---

### Módulos del Sistema

| Componente | Directorio | Descripción Técnica | Stack Principal |
| :--- | :--- | :--- | :--- |
| **[Backend API REST](./backend)** | `backend/` | Servidor central con seguridad JWT, validación de vectores CVSS, control de concurrencia, gestión de proveedores DORA y ejecución de escáneres de dependencias en segundo plano. | `Java 21` `Spring Boot` `Maven` `JPA / JDBC` |
| **[Cliente Web SPA](./desktop-client)** | `desktop-client/` | Interfaz de administración y análisis con filtros combinados, gestión del ciclo de remediación, gráficos interactivos y generación de informes. | `Ionic` `Angular` `TypeScript` |
| **[Aplicación Móvil](./android-app)** | `android-app/` | Cliente móvil Android para consulta en movilidad, filtrado de vulnerabilidades, cambio de estado de remediación y sincronización en caché local. | `Ionic` `Capacitor` `Android SDK` |
| **[Capa de Datos](./database)** | `database/` `data/` | Esquema relacional SQL reproducible, lotes JSON sintéticos/CVE públicos para carga transaccional y manifiestos de prueba para auditoría con Trivy/OSV. | `PostgreSQL 16` `SQL` `JSON` |
| **[Infraestructura CI/CD](./.github/workflows)** | `.github/workflows/` | Pipeline automatizado de compilación, verificación de limpieza de repositorio y análisis estático de vulnerabilidades en dependencias. | `GitHub Actions` `Docker` `Trivy` |

---



### Estructura del Repositorio

```text
vulnfollowup/
├── .github/workflows/   # Pipeline CI/CD y escaneo de seguridad con Trivy
├── android-app/         # Proyecto nativo/híbrido Android y generación de APK (PMDM)
├── api/                 # Documentación del contrato HTTP/REST y ejemplos de peticiones
├── backend/             # Servidor Java Spring Boot: API REST, concurrencia y lógica DORA (PSP + AD + SGE)
├── data/                # Ficheros JSON de carga inicial y directorio audit-target para escáner
├── database/            # Script init.sql de creación de esquema y carga base (AD)
├── desktop-client/      # Aplicación Web SPA en Ionic + Angular (DI)
├── docs/                # Evidencias y memorias técnicas por módulo
│   ├── ad/              # Diagrama Entidad-Relación y pruebas transaccionales
│   ├── di/wireframes/   # Bocetos visuales y guía de estilo accesible (WCAG 2.1 AA)
│   ├── digitalizacion/  # Informe de transformación digital en el sector financiero y DORA
│   ├── english/         # Glosario técnico bilingüe, Executive Summary y guiones
│   ├── ipe/             # Actas de seguimiento semanal, planificación y Lean Canvas
│   ├── sge/             # Diagrama BPMN de gestión de proveedores TIC
│   └── sostenibilidad/  # Mediciones de consumo de red antes/después y relación con los ODS
├── docker-compose.yml   # Despliegue local reproducible de PostgreSQL 16
└── README.md            # Documentación técnica general del proyecto
