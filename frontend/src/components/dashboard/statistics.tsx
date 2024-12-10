'use client';

import { Card } from "@/components/ui/card";
import { ScanReport } from "@/types";
import { AlertTriangle, ShieldAlert, ShieldCheck } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

interface StatisticsProps {
  reports: ScanReport[];
}

export function Statistics({ reports }: StatisticsProps) {
  const criticalCount = reports.reduce(
    (acc, report) => acc + report.vulnerabilities.filter((v) => v.risk_level === "critical").length,
    0
  );
  const mediumCount = reports.reduce(
    (acc, report) => acc + report.vulnerabilities.filter((v) => v.risk_level === "medium").length,
    0
  );
  const lowCount = reports.reduce(
    (acc, report) => acc + report.vulnerabilities.filter((v) => v.risk_level === "low").length,
    0
  );

  const total = criticalCount + mediumCount + lowCount;
  const criticalPercentage = total > 0 ? (criticalCount / total) * 100 : 0;
  const mediumPercentage = total > 0 ? (mediumCount / total) * 100 : 0;
  const lowPercentage = total > 0 ? (lowCount / total) * 100 : 0;

  const riskLevelStyles = {
    critical: {
      bg: "bg-rose-100 dark:bg-rose-950",
      text: "text-rose-700 dark:text-rose-200",
    },
    medium: {
      bg: "bg-amber-100 dark:bg-amber-950",
      text: "text-amber-700 dark:text-amber-200",
    },
    low: {
      bg: "bg-emerald-100 dark:bg-emerald-950",
      text: "text-emerald-700 dark:text-emerald-200",
    },
  };

  return (
    <>
      <Card className={cn(
        "p-6 bg-card border-border",
        "transition-all duration-200 ease-in-out",
        "hover:shadow-lg"
      )}>
        <div className="flex items-center space-x-4">
          <div className={cn(
            "rounded-full w-12 h-12 flex items-center justify-center",
            riskLevelStyles.critical.bg,
            riskLevelStyles.critical.text,
            "font-semibold text-lg"
          )}>
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Critical Vulnerabilities</p>
            <div className="flex items-baseline space-x-2">
              <p className="text-3xl font-bold text-rose-700 dark:text-rose-200">{criticalCount}</p>
              <p className="text-sm text-muted-foreground">issues</p>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <Progress value={criticalPercentage} className="h-2 bg-rose-100 dark:bg-rose-950" indicatorClassName="bg-rose-700 dark:bg-rose-200" />
        </div>
      </Card>

      <Card className={cn(
        "p-6 bg-card border-border",
        "transition-all duration-200 ease-in-out",
        "hover:shadow-lg"
      )}>
        <div className="flex items-center space-x-4">
          <div className={cn(
            "rounded-full w-12 h-12 flex items-center justify-center",
            riskLevelStyles.medium.bg,
            riskLevelStyles.medium.text,
            "font-semibold text-lg"
          )}>
            <AlertTriangle className="h-6 w-6" />
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Medium Vulnerabilities</p>
            <div className="flex items-baseline space-x-2">
              <p className="text-3xl font-bold text-amber-700 dark:text-amber-200">{mediumCount}</p>
              <p className="text-sm text-muted-foreground">issues</p>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <Progress value={mediumPercentage} className="h-2 bg-amber-100 dark:bg-amber-950" indicatorClassName="bg-amber-700 dark:bg-amber-200" />
        </div>
      </Card>

      <Card className={cn(
        "p-6 bg-card border-border",
        "transition-all duration-200 ease-in-out",
        "hover:shadow-lg"
      )}>
        <div className="flex items-center space-x-4">
          <div className={cn(
            "rounded-full w-12 h-12 flex items-center justify-center",
            riskLevelStyles.low.bg,
            riskLevelStyles.low.text,
            "font-semibold text-lg"
          )}>
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground">Low Vulnerabilities</p>
            <div className="flex items-baseline space-x-2">
              <p className="text-3xl font-bold text-emerald-700 dark:text-emerald-200">{lowCount}</p>
              <p className="text-sm text-muted-foreground">issues</p>
            </div>
          </div>
        </div>
        <div className="mt-4">
          <Progress value={lowPercentage} className="h-2 bg-emerald-100 dark:bg-emerald-950" indicatorClassName="bg-emerald-700 dark:bg-emerald-200" />
        </div>
      </Card>
    </>
  );
}
