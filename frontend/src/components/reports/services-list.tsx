'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Service } from '@/types';
import { BarChart } from '@tremor/react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

interface ServicesListProps {
  services: Service[];
}

export function ServicesList({ services }: ServicesListProps) {
  // Group services by protocol for the chart
  const protocolData = services.reduce((acc: Record<string, number>, service) => {
    acc[service.protocol] = (acc[service.protocol] || 0) + 1;
    return acc;
  }, {});

  const chartData = Object.entries(protocolData).map(([protocol, count]) => ({
    name: protocol.toUpperCase(),
    'Services': count,
  }));

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Services by Protocol</CardTitle>
        </CardHeader>
        <CardContent>
          <BarChart
            data={chartData}
            index="name"
            categories={["Services"]}
            colors={["blue"]}
            className="h-64"
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Detected Services</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Port</TableHead>
                <TableHead>Service</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Protocol</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {services.map((service, index) => (
                <TableRow key={index}>
                  <TableCell>{service.port}</TableCell>
                  <TableCell className="font-medium">{service.name}</TableCell>
                  <TableCell>{service.version || 'Unknown'}</TableCell>
                  <TableCell>{service.protocol.toUpperCase()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
