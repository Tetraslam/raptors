'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Service } from '@/types';
import { BarChart } from '@tremor/react';
import { useTheme } from 'next-themes';

interface ServicesChartProps {
  services: Service[];
}

export function ServicesChart({ services }: ServicesChartProps) {
  const { theme } = useTheme();
  
  const protocolCounts = services.reduce((acc, service) => {
    const protocol = service.protocol.toUpperCase();
    acc[protocol] = (acc[protocol] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const chartData = Object.entries(protocolCounts).map(([protocol, count]) => ({
    protocol,
    'Services': count,
  }));

  const customColors = theme === 'dark' ? ['#ffffff'] : ['#000000'];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Services by Protocol</CardTitle>
      </CardHeader>
      <CardContent>
        <BarChart
          data={chartData}
          index="protocol"
          categories={['Services']}
          colors={customColors}
          showLegend={false}
          className="h-48 dark:[&_text]:!fill-white dark:[&_.axis-tick]:!text-white"
        />
      </CardContent>
    </Card>
  );
}
