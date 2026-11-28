-- Usuarios de desarrollo con contraseñas conocidas. Solo para entornos locales y CI:
-- en producción FLYWAY_LOCATIONS debe excluir classpath:db/dev.
INSERT INTO users (email, password_hash, role) VALUES
    ('admin@vulnfollowup.local', '$2a$10$7tFP8ny.tOlgU1RXR3eMVeHnF7Q4l9CRSl/Hwp5PGmYHCRK7ssj1K', 'ADMIN'),
    ('analyst@vulnfollowup.local', '$2a$10$LRYPyt7a/WoEqbZMOUaqwOvniJdoQ7IMXfO3vOIw2s9EZcVi5mmFy', 'ANALYST'),
    ('viewer@vulnfollowup.local', '$2a$10$XH6p67tS2SIDUeINO4dRt./kA3uZPa.s/nIvbCBkP1nABm1UyYwmC', 'VIEWER')
ON CONFLICT (email) DO NOTHING;
