"use client";

import { FormEvent, useState } from "react";
import { ErrorState, LoadingState } from "@/components/page-states";
import { SectionHeader } from "@/components/section-header";
import { useApiData } from "@/hooks/use-api-data";
import { DetectionSettings, updateDetectionSettings } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import styles from "./settings.module.css";

type FormValues = {
  portScanPorts: number;
  portScanSeconds: number;
  bandwidthMegabytes: number;
  bandwidthMinutes: number;
  connectionCount: number;
  connectionSeconds: number;
};

const recommended: FormValues = {
  portScanPorts: 25,
  portScanSeconds: 10,
  bandwidthMegabytes: 500,
  bandwidthMinutes: 5,
  connectionCount: 500,
  connectionSeconds: 60,
};

function toFormValues(settings: DetectionSettings): FormValues {
  return {
    portScanPorts: settings.port_scan_unique_ports,
    portScanSeconds: settings.port_scan_window_seconds,
    bandwidthMegabytes: settings.bandwidth_spike_megabytes,
    bandwidthMinutes: settings.bandwidth_spike_window_seconds / 60,
    connectionCount: settings.connection_spike_connections,
    connectionSeconds: settings.connection_spike_window_seconds,
  };
}

function SettingField({ label, unit, value, min, max, explanation, onChange }: {
  label: string; unit: string; value: number; min: number; max: number;
  explanation: string; onChange: (value: number) => void;
}) {
  return <label className={styles.field}>
    <span>{label}</span>
    <div className={styles.inputGroup}><input required type="number" min={min} max={max} step="1" value={value} onChange={(event) => onChange(Number(event.target.value))} /><b>{unit}</b></div>
    <small>{explanation}</small>
  </label>;
}

function SettingsForm({ initial }: { initial: DetectionSettings }) {
  const [values, setValues] = useState<FormValues>(() => toFormValues(initial));
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<"saved" | "error" | null>(null);
  const [lastUpdated, setLastUpdated] = useState(initial.updated_at);
  const update = (field: keyof FormValues, value: number) => setValues((current) => ({ ...current, [field]: value }));

  async function save(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setResult(null);
    try {
      const saved = await updateDetectionSettings({
        port_scan_unique_ports: values.portScanPorts,
        port_scan_window_seconds: values.portScanSeconds,
        bandwidth_spike_megabytes: values.bandwidthMegabytes,
        bandwidth_spike_window_seconds: Math.round(values.bandwidthMinutes * 60),
        connection_spike_connections: values.connectionCount,
        connection_spike_window_seconds: values.connectionSeconds,
      });
      setLastUpdated(saved.updated_at);
      setResult("saved");
    } catch {
      setResult("error");
    } finally {
      setSaving(false);
    }
  }

  return <form onSubmit={save}>
    <div className={styles.notice}><strong>How threshold changes behave</strong><p>Lower thresholds or longer windows make rules more sensitive and may produce more alerts. Higher thresholds or shorter windows require a stronger, faster pattern before NetSentinel creates a signal. Changes apply to newly evaluated traffic and do not rewrite existing alerts.</p></div>
    <div className={styles.ruleGrid}>
      <section className={styles.ruleCard}><header><span>01</span><div><p className="kicker">RECONNAISSANCE SIGNAL</p><h2>Possible port scan</h2></div></header><p>Signals when one source contacts many distinct destination ports during a short interval.</p><div className={styles.fields}>
        <SettingField label="Unique port threshold" unit="ports" value={values.portScanPorts} min={2} max={65535} onChange={(value) => update("portScanPorts", value)} explanation="Increasing this requires more different ports and reduces sensitivity. Decreasing it identifies smaller scans but can flag ordinary service discovery." />
        <SettingField label="Observation window" unit="seconds" value={values.portScanSeconds} min={1} max={3600} onChange={(value) => update("portScanSeconds", value)} explanation="Increasing the window can identify slower scanning patterns. Decreasing it focuses the rule on rapid bursts." />
      </div><footer>Current rule: {values.portScanPorts} unique ports within {values.portScanSeconds} seconds</footer></section>

      <section className={styles.ruleCard}><header><span>02</span><div><p className="kicker">TRANSFER VOLUME SIGNAL</p><h2>Bandwidth spike</h2></div></header><p>Aggregates inbound or outbound bytes for a local host during the selected interval.</p><div className={styles.fields}>
        <SettingField label="Transfer threshold" unit="MB" value={values.bandwidthMegabytes} min={1} max={1000000} onChange={(value) => update("bandwidthMegabytes", value)} explanation="Increasing this limits signals to larger transfers. Decreasing it detects smaller volume changes but may include routine downloads or synchronization." />
        <SettingField label="Aggregation window" unit="minutes" value={values.bandwidthMinutes} min={1} max={1440} onChange={(value) => update("bandwidthMinutes", value)} explanation="Increasing the window accumulates traffic for longer and makes sustained transfers easier to flag. Decreasing it emphasizes short, concentrated spikes." />
      </div><footer>Current rule: {values.bandwidthMegabytes} MB within {values.bandwidthMinutes} minutes</footer></section>

      <section className={styles.ruleCard}><header><span>03</span><div><p className="kicker">ACTIVITY RATE SIGNAL</p><h2>Connection spike</h2></div></header><p>Compares a host&apos;s recent completed connections with its baseline and this minimum count.</p><div className={styles.fields}>
        <SettingField label="Connection threshold" unit="connections" value={values.connectionCount} min={2} max={1000000} onChange={(value) => update("connectionCount", value)} explanation="Increasing this requires a larger burst and reduces alert volume. Decreasing it makes the rule more sensitive to moderate activity changes." />
        <SettingField label="Observation window" unit="seconds" value={values.connectionSeconds} min={1} max={3600} onChange={(value) => update("connectionSeconds", value)} explanation="Increasing the window counts connections over more time. Decreasing it focuses detection on faster, denser bursts." />
      </div><footer>Current rule: {values.connectionCount} connections within {values.connectionSeconds} seconds</footer></section>
    </div>
    <div className={styles.actions}><div>{result === "saved" && <span className={styles.success}>Settings saved and active.</span>}{result === "error" && <span className={styles.failure}>Settings could not be saved. Check the values and try again.</span>}<small>Last database update: {formatDateTime(lastUpdated)}</small></div><button className={styles.reset} type="button" onClick={() => { setValues(recommended); setResult(null); }}>Restore recommended values</button><button className="button" disabled={saving} type="submit">{saving ? "Saving…" : "Save detection settings"}</button></div>
  </form>;
}

export default function SettingsPage() {
  const { data, loading, error, reload } = useApiData<DetectionSettings>("/api/settings/detection", 60_000);
  return <>
    <SectionHeader eyebrow="SYSTEM / DETECTION" title="Detection settings" description="Tune defensive metadata rules to match the normal scale and behavior of your network." />
    {loading && !data ? <LoadingState rows={7} /> : error && !data ? <ErrorState onRetry={reload} /> : data && <SettingsForm key={data.updated_at} initial={data} />}
  </>;
}
