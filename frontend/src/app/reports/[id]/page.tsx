'use client';

import { VulnerabilityChart } from '@/components/reports/vulnerability-chart';
import { ServicesList } from '@/components/reports/services-list';
import { getReport } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';
import useSWR from 'swr';
import { formatDistanceToNow } from 'date-fns';

export default function ReportPage({ params }: { params: { id: string } }) {
  const { data: report } = useSWR(`/reports/${params.id}`, () => getReport(params.id), {
    refreshInterval: 5000,
  });

  if (!report) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      <div className="flex items-center gap-4">
        <Link href="/" passHref>
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <h1 className="text-4xl font-bold">Scan Report</h1>
          <p className="text-muted-foreground">
            {report.host} • {formatDistanceToNow(new Date(report.scan_timestamp), { addSuffix: true })}
          </p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Critical</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-rose-600 dark:text-rose-400">
              {report.risk_summary.critical}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Medium</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-amber-600 dark:text-amber-400">
              {report.risk_summary.medium}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Low</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-emerald-600 dark:text-emerald-400">
              {report.risk_summary.low}
            </div>
          </CardContent>
        </Card>
      </div>

      <VulnerabilityChart vulnerabilities={report.vulnerabilities} />
      
      <ServicesList services={report.services} />

      <Card>
        <CardHeader>
          <CardTitle>Vulnerabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {report.vulnerabilities.map((vuln) => (
              <div
                key={vuln.cve_id}
                className="p-4 rounded-lg border bg-card"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold">{vuln.cve_id}</h3>
                    <p className="text-sm text-muted-foreground">{vuln.description}</p>
                  </div>
                  <div className={`px-3 py-1 rounded-full text-sm font-medium
                    ${vuln.risk_level === 'critical' ? 'bg-rose-100 dark:bg-rose-900 text-rose-700 dark:text-rose-200' :
                      vuln.risk_level === 'medium' ? 'bg-amber-100 dark:bg-amber-900 text-amber-700 dark:text-amber-200' :
                        'bg-emerald-100 dark:bg-emerald-900 text-emerald-700 dark:text-emerald-200'
                    }`}
                  >
                    {vuln.risk_level}
                  </div>
                </div>
                {vuln.affected_versions && vuln.affected_versions.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-sm font-medium mb-2">Affected Versions</h4>
                    <div className="flex flex-wrap gap-2">
                      {vuln.affected_versions.map((version, i) => (
                        <span
                          key={i}
                          className="px-2 py-1 text-xs rounded-md bg-secondary text-secondary-foreground"
                        >
                          {version}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {vuln.fix_suggestions && (
                  <div className="mt-4">
                    <h4 className="text-sm font-medium mb-2">Fix Suggestions</h4>
                    <p className="text-sm text-muted-foreground">{vuln.fix_suggestions}</p>
                  </div>
                )}
                {vuln.reference_urls && vuln.reference_urls.length > 0 && (
                  <div className="mt-4">
                    <h4 className="text-sm font-medium mb-2">References</h4>
                    <div className="space-y-1">
                      {vuln.reference_urls.map((url, i) => (
                        <a
                          key={i}
                          href={url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm text-blue-600 dark:text-blue-400 hover:underline block"
                        >
                          {url}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
