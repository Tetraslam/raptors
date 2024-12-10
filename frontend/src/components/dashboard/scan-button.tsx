'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { startScan } from '@/lib/api';
import { Loader2, Play } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function ScanButton() {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [target, setTarget] = useState('');

  const handleScan = async () => {
    if (!target) {
      toast.error('Please enter a target host');
      return;
    }

    console.log('Starting scan for target:', target);
    try {
      setLoading(true);
      const response = await startScan({ host: target });
      console.log('Scan response:', response);
      toast.success(response.message || 'Scan started successfully');
      setOpen(false);
      setTarget('');
    } catch (error) {
      console.error('Scan error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          className={cn(
            'gap-2 px-4 py-2',
            'bg-primary text-primary-foreground hover:bg-primary/90',
            'transition-all duration-200 ease-in-out',
            'shadow-sm hover:shadow-md'
          )}
        >
          <Play className="h-4 w-4" />
          Start New Scan
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle className="text-xl font-semibold tracking-tight">Start New Vulnerability Scan</DialogTitle>
          <DialogDescription className="text-muted-foreground">
            Enter the target host or IP address to begin scanning for vulnerabilities.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="space-y-2">
            <Label htmlFor="target" className="text-sm font-medium">
              Target Host
            </Label>
            <Input
              id="target"
              placeholder="example.com or 192.168.1.1"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className={cn(
                'w-full px-3 py-2',
                'bg-background border-input',
                'focus:ring-2 focus:ring-ring focus:ring-offset-2',
                'transition-all duration-200'
              )}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            type="button"
            onClick={() => {
              console.log('Button clicked');
              handleScan();
            }}
            disabled={loading || !target}
            className={cn(
              'gap-2 px-4 py-2',
              'bg-primary text-primary-foreground hover:bg-primary/90',
              'transition-all duration-200 ease-in-out',
              'shadow-sm hover:shadow-md',
              loading && 'opacity-50 cursor-not-allowed'
            )}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            Start Scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
