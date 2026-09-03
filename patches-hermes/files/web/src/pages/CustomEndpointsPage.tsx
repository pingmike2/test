import { useCallback, useEffect, useState } from "react";
import {
  CheckCircle2,
  KeyRound,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Trash2,
  ExternalLink,
  Plug,
} from "lucide-react";
import { Badge } from "@nous-research/ui/ui/components/badge";
import { Button } from "@nous-research/ui/ui/components/button";
import { Card, CardContent } from "@nous-research/ui/ui/components/card";
import { Spinner } from "@nous-research/ui/ui/components/spinner";
import { useToast } from "@nous-research/ui/hooks/use-toast";
import { DeleteConfirmDialog } from "@/components/DeleteConfirmDialog";
import { useI18n } from "@/i18n";
import { EndpointFormDialog } from "@/components/EndpointFormDialog";

interface CustomEndpoint {
  id: string;
  name: string;
  base_url: string;
  model: string;
  models: string[];
  context_length: number | null;
  discover_models: boolean;
  has_api_key: boolean;
  api_key_preview: string;
  is_current: boolean;
  source: string;
}

interface EndpointsResponse {
  endpoints: CustomEndpoint[];
  current: { provider: string; model: string; base_url: string };
}

async function apiFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const token = (window as any).__HERMES_SESSION_TOKEN__ ?? "";
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(url, { ...init, headers, credentials: "include" });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  return res.json();
}

export default function CustomEndpointsPage() {
  const { t } = useI18n();
  const { showToast } = useToast();

  const [endpoints, setEndpoints] = useState<CustomEndpoint[]>([]);
  const [current, setCurrent] = useState<{ provider: string; model: string; base_url: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { ok: boolean; msg: string }>>({});
  const [editTarget, setEditTarget] = useState<CustomEndpoint | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch<EndpointsResponse>("/api/providers/custom-endpoints");
      setEndpoints(res.endpoints);
      setCurrent(res.current);
    } catch {
      showToast(t.endpoints.loadFail, "error");
    } finally {
      setLoading(false);
    }
  }, [showToast, t.endpoints.loadFail]);

  useEffect(() => { load(); }, [load]);

  const activate = useCallback(async (id: string) => {
    try {
      const res = await apiFetch<EndpointsResponse>(`/api/providers/custom-endpoints/${encodeURIComponent(id)}/activate`, { method: "POST" });
      if (res.endpoints) setEndpoints(res.endpoints);
      if (res.current) setCurrent(res.current);
      showToast(t.endpoints.activateOk, "success");
    } catch (err) {
      showToast(`${t.endpoints.activateFail}: ${String(err)}`, "error");
    }
  }, [showToast, t.endpoints.activateFail, t.endpoints.activateOk]);

  const test = useCallback(async (ep: CustomEndpoint) => {
    setTesting(ep.id);
    try {
      const res = await apiFetch<{ ok: boolean; reachable: boolean; message?: string; models?: string[] }>("/api/providers/custom-endpoints/validate", {
        method: "POST",
        body: JSON.stringify({ id: ep.id, name: ep.name, base_url: ep.base_url, model: ep.model, api_key: "", discover_models: false }),
      });
      const msg = res.message || (res.ok ? t.endpoints.testOk : t.endpoints.testFail);
      setTestResults(prev => ({ ...prev, [ep.id]: { ok: res.ok, msg } }));
      showToast(res.ok ? t.endpoints.testOk : msg, res.ok ? "success" : "error");
    } catch (err) {
      const msg = `Error: ${String(err)}`;
      setTestResults(prev => ({ ...prev, [ep.id]: { ok: false, msg } }));
      showToast(t.endpoints.testFail, "error");
    } finally {
      setTesting(null);
    }
  }, [showToast, t.endpoints.testOk, t.endpoints.testFail]);

  const doDelete = useCallback(async () => {
    if (!deleteTarget) return;
    try {
      const res = await apiFetch<{ ok: boolean }>(`/api/providers/custom-endpoints/${encodeURIComponent(deleteTarget)}`, { method: "DELETE" });
      if (res.ok) {
        setEndpoints(prev => prev.filter(e => e.id !== deleteTarget));
        showToast(t.endpoints.deleteOk, "success");
      }
    } catch {
      showToast(t.endpoints.deleteFail, "error");
    } finally {
      setDeleteTarget(null);
    }
  }, [deleteTarget, showToast, t.endpoints.deleteOk, t.endpoints.deleteFail]);

  const onSaved = useCallback(() => {
    setShowForm(false);
    setEditTarget(null);
    load();
  }, [load]);

  if (loading) return <Spinner />;

  return (
    <div className="space-y-3 px-3 py-4 sm:space-y-4 sm:p-6">
      {/* header */}
      <div className="flex items-center justify-between">
        <Button outlined size="sm" onClick={load} title="Refresh">
          <RefreshCw className="h-4 w-4" />
        </Button>
        <Button size="sm" onClick={() => { setEditTarget(null); setShowForm(true); }}>
          <Plus className="mr-1 h-4 w-4" /> {t.endpoints.addButton}
        </Button>
      </div>

      {endpoints.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-12 text-center text-muted-foreground">
            <Plug className="h-8 w-8" />
            <p className="text-base font-medium">{t.endpoints.noEndpoints}</p>
            <p className="text-sm">{t.endpoints.noEndpointsHint}</p>
          </CardContent>
        </Card>
      ) : (
        <div className="flex flex-col gap-2 sm:gap-3">
          {endpoints.map((ep) => {
            const isActive = current?.provider === ep.id;
            return (
              <Card key={ep.id} className={isActive ? "border-primary" : ""}>
                <CardContent className="space-y-2 px-3 py-3 sm:px-4 sm:py-4">
                  {/* top row: name + badge */}
                  <div className="flex items-center gap-2">
                    <span className="min-w-0 flex-1 truncate text-sm font-medium sm:text-base">{ep.name}</span>
                    {isActive && (
                      <Badge tone="success" className="shrink-0 text-xs">
                        <CheckCircle2 className="mr-0.5 h-3 w-3" /> {t.endpoints.currentlyActive}
                      </Badge>
                    )}
                  </div>

                  {/* base_url (truncate) */}
                  <p className="truncate text-xs text-muted-foreground">{ep.base_url}</p>

                  {/* model + key indicator */}
                  <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                    <span className="font-medium">{ep.model}</span>
                    {ep.has_api_key && <KeyRound className="h-3 w-3" />}
                    {ep.models && ep.models.length > 1 && (
                      <span>{ep.models.length} models</span>
                    )}
                  </div>

                  {/* action buttons: row, wrap on small screens */}
                  <div className="flex flex-wrap items-center gap-1 pt-1 sm:gap-1.5">
                    <Button ghost size="sm" onClick={() => test(ep)} disabled={testing === ep.id} title="Test">
                      {testing === ep.id ? <Spinner className="h-3.5 w-3.5" /> : <ExternalLink className="h-3.5 w-3.5" />}
                      <span className="ml-1 text-xs">{t.endpoints.test}</span>
                    </Button>
                    {!isActive && (
                      <Button ghost size="sm" onClick={() => activate(ep.id)} title="Activate">
                        <Power className="h-3.5 w-3.5" />
                        <span className="ml-1 text-xs">Activate</span>
                      </Button>
                    )}
                    <Button ghost size="sm" onClick={() => { setEditTarget(ep); setShowForm(true); }} title="Edit">
                      <Pencil className="h-3.5 w-3.5" />
                      <span className="ml-1 text-xs">Edit</span>
                    </Button>
                    <Button ghost size="sm" onClick={() => setDeleteTarget(ep.id)} title="Delete">
                      <Trash2 className="h-3.5 w-3.5 text-destructive" />
                      <span className="ml-1 text-xs">Delete</span>
                    </Button>
                  </div>

                  {/* inline test result feedback */}
                  {testResults[ep.id] && (
                    <p className={`text-xs ${testResults[ep.id].ok ? "text-green-600" : "text-red-500"}`}>
                      {testResults[ep.id].msg}
                    </p>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {showForm && (
        <EndpointFormDialog
          endpoint={editTarget}
          onClose={() => { setShowForm(false); setEditTarget(null); }}
          onSaved={onSaved}
        />
      )}

      {deleteTarget && (
        <DeleteConfirmDialog
          open
          loading={false}
          onCancel={() => setDeleteTarget(null)}
          onConfirm={doDelete}
          title={t.endpoints.deleteConfirm}
        />
      )}
    </div>
  );
}