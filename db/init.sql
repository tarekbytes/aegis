-- Aegis Database Schema
-- Dialect: PostgreSQL

-- =============================================
-- Table: projects
-- Stores the core information about each project being tracked.
-- =============================================
CREATE TABLE projects (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =============================================
-- Table: dependencies
-- A master catalog of every unique library package (e.g., 'requests', 'numpy').
-- This table is version-agnostic.
-- =============================================
CREATE TABLE dependencies (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

-- =============================================
-- Table: project_dependencies
-- This is the core junction table linking a project to a specific version of a dependency.
-- It also holds the cache data from osv.dev.
-- =============================================
CREATE TABLE project_dependencies (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL,
    dependency_id INTEGER NOT NULL,
    version TEXT NOT NULL,
    -- Caching columns
    last_scanned_at TIMESTAMPTZ,
    cached_vulnerabilities_json JSONB,

    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE CASCADE,

    -- Ensures a project cannot have the same version of a dependency listed twice.
    UNIQUE (project_id, dependency_id, version)
);

-- Indexes for performance on foreign key lookups
CREATE INDEX idx_project_dependencies_project_id ON project_dependencies(project_id);
CREATE INDEX idx_project_dependencies_dependency_id ON project_dependencies(dependency_id);


-- =============================================
-- Table: vulnerabilities
-- Stores structured information about a single, unique vulnerability (e.g., a specific CVE).
-- This allows for cross-project queries like "find all projects affected by this CVE".
-- =============================================
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    external_id TEXT NOT NULL UNIQUE, -- e.g., 'CVE-2023-1234' or 'GHSA-abcd-1234-wxyz'
    summary TEXT,
    details_json JSONB -- Stores the full, rich vulnerability data from OSV.
);


-- =============================================
-- Table: project_dependency_vulnerabilities
-- A many-to-many junction table that links a specific dependency in a project
-- to a known vulnerability.
-- =============================================
CREATE TABLE project_dependency_vulnerabilities (
    project_dependency_id INTEGER NOT NULL,
    vulnerability_id INTEGER NOT NULL,

    FOREIGN KEY (project_dependency_id) REFERENCES project_dependencies(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,

    -- The primary key prevents duplicate entries.
    PRIMARY KEY (project_dependency_id, vulnerability_id)
);

-- Indexes for performance
CREATE INDEX idx_pdv_project_dependency_id ON project_dependency_vulnerabilities(project_dependency_id);
CREATE INDEX idx_pdv_vulnerability_id ON project_dependency_vulnerabilities(vulnerability_id); 
