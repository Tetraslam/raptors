import { ScanReport, ScanRequest } from '@/types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || '/api';

export async function startScan(data: ScanRequest): Promise<{ message: string }> {
  const response = await fetch(`${API_URL}/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  });

  const responseData = await response.json();

  if (!response.ok) {
    throw new Error(responseData.detail || 'Failed to start scan');
  }

  return responseData;
}

export async function getReports(): Promise<ScanReport[]> {
  const response = await fetch(`${API_URL}/reports`);
  if (!response.ok) {
    throw new Error('Failed to fetch reports');
  }
  return response.json();
}

export async function getReport(id: string): Promise<ScanReport> {
  const response = await fetch(`${API_URL}/reports/${id}`);
  if (!response.ok) {
    throw new Error('Failed to fetch report');
  }
  return response.json();
}

export async function deleteReport(id: string): Promise<void> {
  const response = await fetch(`${API_URL}/reports/${id}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    throw new Error('Failed to delete report');
  }
}
