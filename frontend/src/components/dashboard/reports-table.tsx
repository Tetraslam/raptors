'use client';

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ScanReport } from '@/types';
import { formatDistanceToNow } from 'date-fns';
import { ArrowRight, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { deleteReport } from '@/lib/api';
import Link from 'next/link';

interface ReportsTableProps {
  reports: ScanReport[];
  onReportDeleted: () => void;
}

export function ReportsTable({ reports, onReportDeleted }: ReportsTableProps) {
  const handleDelete = async (id: string) => {
    try {
      await deleteReport(id);
      onReportDeleted();
    } catch (error) {
      console.error('Failed to delete report:', error);
    }
  };

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Host</TableHead>
            <TableHead>Scan Time</TableHead>
            <TableHead className="text-center">Critical</TableHead>
            <TableHead className="text-center">Medium</TableHead>
            <TableHead className="text-center">Low</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {reports.map((report) => (
            <TableRow key={report.id}>
              <TableCell className="font-medium">{report.host}</TableCell>
              <TableCell>{formatDistanceToNow(new Date(report.scan_timestamp), { addSuffix: true })}</TableCell>
              <TableCell className="text-center">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-rose-100 dark:bg-rose-900 text-rose-600 dark:text-rose-200">
                  {report.risk_summary.critical}
                </span>
              </TableCell>
              <TableCell className="text-center">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-amber-100 dark:bg-amber-900 text-amber-600 dark:text-amber-200">
                  {report.risk_summary.medium}
                </span>
              </TableCell>
              <TableCell className="text-center">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-900 text-emerald-600 dark:text-emerald-200">
                  {report.risk_summary.low}
                </span>
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-2">
                  <Link href={`/reports/${report.id}`} passHref>
                    <Button variant="ghost" size="icon">
                      <ArrowRight className="h-4 w-4" />
                    </Button>
                  </Link>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => report.id && handleDelete(report.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
