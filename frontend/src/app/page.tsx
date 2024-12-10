'use client';

import { ScanButton } from '@/components/dashboard/scan-button';
import { Statistics } from '@/components/dashboard/statistics';
import { ReportsTable } from '@/components/dashboard/reports-table';
import { getReports } from '@/lib/api';
import useSWR from 'swr';
import { Card } from "@/components/ui/card";
import { cn } from '@/lib/utils';
import { Navbar } from "@/components/layout/navbar";

export default function Home() {
  const { data: reports = [], mutate } = useSWR('/reports', () => getReports(), {
    refreshInterval: 5000, // Refresh every 5 seconds
  });

  return (
    <>
      <Navbar />
      <div className="container mx-auto p-6 space-y-8">
        <Card className={cn(
          "p-6 bg-card border-border",
          "transition-all duration-200 ease-in-out",
          "hover:shadow-lg"
        )}>
          <div className="flex justify-between items-center">
            <div className="space-y-2">
              <h1 className="text-4xl font-bold tracking-tight text-foreground">
                Vulnerability Scanner
              </h1>
              <p className="text-lg text-muted-foreground">
                Monitor and analyze system vulnerabilities in real-time
              </p>
            </div>
            <ScanButton />
          </div>
        </Card>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          <Statistics reports={reports} />
        </div>

        <Card className={cn(
          "p-6 bg-card border-border",
          "transition-all duration-200 ease-in-out",
          "hover:shadow-lg"
        )}>
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-2xl font-semibold tracking-tight text-foreground">Recent Scans</h2>
            </div>
            <ReportsTable reports={reports} onReportDeleted={mutate} />
          </div>
        </Card>
      </div>
    </>
  );
}
