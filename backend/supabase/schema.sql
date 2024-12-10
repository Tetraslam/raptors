-- Enable necessary extensions
create extension if not exists "uuid-ossp";

-- Enum types
create type risk_level as enum ('low', 'medium', 'critical');

-- Services table to store detected services
create table if not exists services (
    id uuid primary key default uuid_generate_v4(),
    port integer not null,
    name text not null,
    version text,
    protocol text not null,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Vulnerabilities table to store detected vulnerabilities
create table if not exists vulnerabilities (
    id uuid primary key default uuid_generate_v4(),
    cve_id text not null,
    description text not null,
    cvss_score float not null,
    risk_level risk_level not null,
    affected_versions text[] default array[]::text[],
    fix_suggestions text,
    reference_urls text[] default array[]::text[],
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Scan reports table to store complete scan reports
create table if not exists scan_reports (
    id uuid primary key default uuid_generate_v4(),
    timestamp timestamp with time zone default timezone('utc'::text, now()) not null,
    host text not null,
    total_vulnerabilities integer default 0,
    risk_summary jsonb not null default '{"low": 0, "medium": 0, "critical": 0}'::jsonb,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Junction table for scan reports and services
create table if not exists scan_report_services (
    scan_report_id uuid references scan_reports(id) on delete cascade,
    service_id uuid references services(id) on delete cascade,
    primary key (scan_report_id, service_id)
);

-- Junction table for scan reports and vulnerabilities
create table if not exists scan_report_vulnerabilities (
    scan_report_id uuid references scan_reports(id) on delete cascade,
    vulnerability_id uuid references vulnerabilities(id) on delete cascade,
    primary key (scan_report_id, vulnerability_id)
);

-- Indexes for better query performance
create index if not exists idx_scan_reports_timestamp on scan_reports(timestamp desc);
create index if not exists idx_vulnerabilities_cve_id on vulnerabilities(cve_id);
create index if not exists idx_services_port on services(port);

-- RLS Policies
alter table scan_reports enable row level security;
alter table services enable row level security;
alter table vulnerabilities enable row level security;
alter table scan_report_services enable row level security;
alter table scan_report_vulnerabilities enable row level security;

-- Create a policy that allows all authenticated users to read all rows
create policy "Allow authenticated users to read scan reports"
    on scan_reports for select
    to authenticated
    using (true);

create policy "Allow authenticated users to read services"
    on services for select
    to authenticated
    using (true);

create policy "Allow authenticated users to read vulnerabilities"
    on vulnerabilities for select
    to authenticated
    using (true);

create policy "Allow authenticated users to read scan report services"
    on scan_report_services for select
    to authenticated
    using (true);

create policy "Allow authenticated users to read scan report vulnerabilities"
    on scan_report_vulnerabilities for select
    to authenticated
    using (true);

-- Create a policy that allows service role to insert/update/delete
create policy "Allow service role to manage scan reports"
    on scan_reports for all
    to service_role
    using (true)
    with check (true);

create policy "Allow service role to manage services"
    on services for all
    to service_role
    using (true)
    with check (true);

create policy "Allow service role to manage vulnerabilities"
    on vulnerabilities for all
    to service_role
    using (true)
    with check (true);

create policy "Allow service role to manage scan report services"
    on scan_report_services for all
    to service_role
    using (true)
    with check (true);

create policy "Allow service role to manage scan report vulnerabilities"
    on scan_report_vulnerabilities for all
    to service_role
    using (true)
    with check (true);

-- Functions
create or replace function get_scan_report_details(report_id uuid)
returns table (
    id uuid,
    scan_timestamp timestamptz,
    host text,
    total_vulnerabilities integer,
    risk_summary jsonb,
    services json,
    vulnerabilities json
) as $$
begin
    return query
    select 
        sr.id,
        sr.timestamp as scan_timestamp,
        sr.host,
        sr.total_vulnerabilities,
        sr.risk_summary,
        (
            select json_agg(json_build_object(
                'id', s.id,
                'port', s.port,
                'name', s.name,
                'version', s.version,
                'protocol', s.protocol
            ))
            from services s
            join scan_report_services srs on s.id = srs.service_id
            where srs.scan_report_id = sr.id
        ) as services,
        (
            select json_agg(json_build_object(
                'id', v.id,
                'cve_id', v.cve_id,
                'description', v.description,
                'cvss_score', v.cvss_score,
                'risk_level', v.risk_level,
                'affected_versions', v.affected_versions,
                'fix_suggestions', v.fix_suggestions,
                'reference_urls', v.reference_urls
            ))
            from vulnerabilities v
            join scan_report_vulnerabilities srv on v.id = srv.vulnerability_id
            where srv.scan_report_id = sr.id
        ) as vulnerabilities
    from scan_reports sr
    where sr.id = report_id;
end;
$$ language plpgsql;
