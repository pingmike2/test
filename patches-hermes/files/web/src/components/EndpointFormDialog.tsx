import { useCallback, useEffect, useMemo, useState } from "react";
import { CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@nous-research/ui/ui/components/button";
import { Input } from "@nous-research/ui/ui/components/input";
import { Label } from "@nous-research/ui/ui/components/label";
import { Switch } from "@nous-research/ui/ui/components/switch";
import { Spinner } from "@nous-research/ui/ui/components/spinner";
import { useToast } from "@nous-research/ui/hooks/use-toast";
import { useI18n } from "@/i18n";

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

interface Props {
  endpoint: CustomEndpoint | null;
  onClose: () => void;
  onSaved: () => void;
}

interface ValidateResult {
  ok: boolean;
  reachable: boolean;
  message?: string;
  models?: string[];
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

export function EndpointFormDialog({ endpoint, onClose, onSaved }: Props) {
  const { t } = useI18n();
  const { showToast } = useToast();

  const [name, setName] = useState(endpoint?.name ?? "");
  const [baseUrl, setBaseUrl] = useState(endpoint?.base_url ?? "");
  const [model, setModel] = useState(endpoint?.model ?? "");
  const [apiKey, setApiKey] = useState("");
  const [discover, setDiscover] = useState(endpoint?.discover_models ?? true);
  const [makeDefault, setMakeDefault] = useState(false);

  const [fetchedModels, setFetchedModels] = useState<string[]>(endpoint?.models ?? []);
  const [filterText, setFilterText] = useState("");
  const [validMsg, setValidMsg] = useState("");
  const [validOk, setValidOk] = useState(false);
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);

  // Live-filter the fetched catalogue. Multiple comma-separated keywords are
  // supported; a model is kept when it matches ANY keyword (e.g.
  // "deepseek-v4-flash, deepseek-v4-pro"). Empty filter = show everything.
  const filterKeywords = useMemo(
    () => filterText.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean),
    [filterText],
  );
  const filteredModels = useMemo(() => {
    if (filterKeywords.length === 0) return fetchedModels;
    return fetchedModels.filter((modelId) => {
      const candidate = modelId.toLowerCase();
      return filterKeywords.some((keyword) => candidate.includes(keyword));
    });
  }, [fetchedModels, filterKeywords]);

  // Keep the default model inside the filtered set; if the filter removes the
  // current default, fall back to the first remaining match.
  useEffect(() => {
    if (filteredModels.length > 0 && !filteredModels.includes(model)) {
      setModel(filteredModels[0]);
    }
  }, [filteredModels, model]);

  // A non-empty filter pins the catalogue — auto-discovery would re-pull the
  // full list on the next picker refresh, undoing the filter. Force it off.
  const filterActive = filterKeywords.length > 0;
  useEffect(() => {
    if (filterActive) setDiscover(false);
  }, [filterActive]);

  const doTest = useCallback(async () => {
    if (!baseUrl.trim()) {
      showToast("Enter an endpoint URL first.", "error");
      return;
    }
    setTesting(true);
    setValidMsg("");
    setValidOk(false);
    try {
      const res = await apiFetch<ValidateResult>("/api/providers/custom-endpoints/validate", {
        method: "POST",
        body: JSON.stringify({ id: endpoint?.id ?? "", name: name || "test", base_url: baseUrl, model, api_key: apiKey || null, discover_models: false }),
      });
      if (res.ok && res.models && res.models.length > 0) {
        setFetchedModels(res.models);
        setModel(res.models[0]);
        setValidOk(true);
        setValidMsg(`${res.models.length} models`);
      } else {
        setFetchedModels([]);
        setValidOk(false);
        setValidMsg(res.message || t.endpoints.testFail);
      }
    } catch (err) {
      setFetchedModels([]);
      setValidOk(false);
      setValidMsg(`Error: ${String(err)}`);
    } finally {
      setTesting(false);
    }
  }, [baseUrl, name, model, apiKey, showToast, t.endpoints.testFail]);

  const doSave = useCallback(async () => {
    if (!baseUrl.trim() || !model.trim()) return;
    setSaving(true);
    try {
      const body = {
        id: endpoint?.id ?? "",
        name: name || baseUrl.replace(/^https?:\/\//, "").split("/")[0],
        base_url: baseUrl,
        model,
        api_key: apiKey || null,
        discover_models: discover,
        make_default: makeDefault,
        ...(filteredModels.length ? { models: filteredModels } : {}),
        ...(filterText.trim() ? { replace_models: true } : {}),
      };
      const res = await apiFetch<{ ok: boolean }>("/api/providers/custom-endpoints", { method: "POST", body: JSON.stringify(body) });
      if (res.ok) {
        showToast(t.endpoints.saveOk, "success");
        onSaved();
      } else {
        showToast(t.endpoints.saveFail, "error");
      }
    } catch {
      showToast(t.endpoints.saveFail, "error");
    } finally {
      setSaving(false);
    }
  }, [name, baseUrl, model, apiKey, discover, makeDefault, fetchedModels, filterText, filteredModels, endpoint, showToast, t.endpoints.saveOk, t.endpoints.saveFail, onSaved]);

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/50">
      <div className="max-h-[80dvh] w-full overflow-y-auto overscroll-contain rounded-t-xl border bg-background p-5 shadow-xl sm:max-w-lg sm:max-h-[85vh] sm:rounded-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold sm:text-lg">
            {endpoint ? `${t.endpoints.formTitle} — ${endpoint.name}` : t.endpoints.formTitle}
          </h2>
          <Button ghost size="sm" onClick={onClose} title={t.common.close} aria-label={t.common.close}>
            <XCircle className="h-5 w-5" />
          </Button>
        </div>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label className="text-xs sm:text-sm">{t.endpoints.formName}</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t.endpoints.formNameHint} />
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs sm:text-sm">{t.endpoints.formBaseUrl}</Label>
            <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder={t.endpoints.formBaseUrlHint} />
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs sm:text-sm">{t.endpoints.formApiKey}</Label>
            <Input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={endpoint?.has_api_key ? "••••••" : t.endpoints.formApiKeyHint} />
            <p className="text-xs text-muted-foreground">{t.endpoints.formApiKeyHint}</p>
          </div>

          <div className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:gap-2">
            <Button outlined size="sm" onClick={doTest} disabled={testing || !baseUrl.trim()} className="self-start">
              {testing ? <Spinner className="mr-1 h-4 w-4" /> : <CheckCircle2 className="mr-1 h-4 w-4" />}
              {testing ? "Fetching…" : "Test & fetch models"}
            </Button>
            {validMsg && (
              <span className={validOk ? "text-xs text-green-600 sm:text-sm" : "text-xs text-red-500 sm:text-sm"}>{validMsg}</span>
            )}
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs sm:text-sm">{t.endpoints.formModel}</Label>
            {fetchedModels.length > 0 ? (
              <>
                <Input
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                  placeholder={t.endpoints.formFilterHint}
                  className="mb-1.5"
                />
                {filteredModels.length > 0 ? (
                  <select
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    className="w-full min-h-[44px] rounded-md border bg-background px-3 py-2.5 text-sm"
                  >
                    {filteredModels.map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                ) : (
                  <p className="text-xs text-red-500">{t.endpoints.formFilterEmpty}</p>
                )}
                <p className="text-xs text-muted-foreground">
                  {filterText.trim() ? `${filteredModels.length} / ${fetchedModels.length}` : `${fetchedModels.length} models`}
                </p>
              </>
            ) : (
              <Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="e.g. qwen3.8-max" />
            )}
          </div>

          <div className="flex items-center justify-between min-h-[44px]">
            <div className="flex flex-col">
              <Label className="text-xs sm:text-sm">{t.endpoints.formDiscover}</Label>
              {filterActive && (
                <span className="text-[11px] text-muted-foreground">{t.endpoints.formFilterPinsDiscover}</span>
              )}
            </div>
            <Switch checked={discover} onCheckedChange={setDiscover} disabled={filterActive} />
          </div>

          <div className="flex items-center justify-between min-h-[44px]">
            <Label className="text-xs sm:text-sm">{t.endpoints.formMakeDefault}</Label>
            <Switch checked={makeDefault} onCheckedChange={setMakeDefault} />
          </div>
        </div>

        <div className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end sm:gap-2">
          <Button ghost onClick={onClose} className="min-h-[44px]">
            <XCircle className="mr-1 h-4 w-4" /> {t.common.cancel}
          </Button>
          <Button onClick={doSave} disabled={saving || !baseUrl.trim() || !model.trim()} className="min-h-[44px]">
            {saving && <Spinner className="mr-1 h-4 w-4" />}
            {t.common.save}
          </Button>
        </div>
      </div>
    </div>
  );
}