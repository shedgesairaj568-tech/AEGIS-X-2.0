import { useCallback, useEffect, useState } from "react";
import type { Alert, AlertFilters, AlertListResponse } from "../types/api";
import { alertsService } from "../services/alertsService";
import { getApiErrorMessage } from "../services/apiClient";

export function useAlerts(filters: AlertFilters) {
  const [data, setData] = useState<AlertListResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAlerts = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await alertsService.list(filters);
      setData(result);
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(filters)]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  return { data, isLoading, error, refetch: fetchAlerts };
}

export function useAllAlertsForStats() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    alertsService
      .list({ page: 1, page_size: 100 })
      .then((result) => {
        if (!cancelled) setAlerts(result.items);
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return { alerts, isLoading };
}
