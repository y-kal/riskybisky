"use client";

import { useEffect, useMemo, useState } from "react";

const API_BASE =
    process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

const VULNERABILITY_SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
};

function getSeverityRank(severity) {
    const normalized = String(severity || "").trim().toLowerCase();
    return VULNERABILITY_SEVERITY_ORDER[normalized] ?? 4;
}

async function fetchJson(path, options) {
    const response = await fetch(`${API_BASE}${path}`, {
        headers: { "Content-Type": "application/json" },
        ...options,
    });
    if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `Request failed: ${response.status}`);
    }
    return response.json();
}

export default function HomePage() {
    const [scanMode, setScanMode] = useState("image");
    const [image, setImage] = useState("nginx:1.27-alpine");
    const [tarFile, setTarFile] = useState(null);
    const [tarImageName, setTarImageName] = useState("");
    const [platform, setPlatform] = useState("linux/amd64");
    const [artifacts, setArtifacts] = useState([]);
    const [selectedKey, setSelectedKey] = useState("");
    const [selectedArtifact, setSelectedArtifact] = useState(null);
    const [job, setJob] = useState(null);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    async function refreshArtifacts() {
        const data = await fetchJson("/api/artifacts");
        setArtifacts(data.items || []);
        if (!selectedKey && data.items && data.items.length > 0) {
            setSelectedKey(data.items[0].artifact_key);
        }
    }

    useEffect(() => {
        refreshArtifacts().catch((err) => setError(err.message));
    }, []);

    useEffect(() => {
        if (!selectedKey) return;
        fetchJson(`/api/artifacts/${selectedKey}`)
            .then(setSelectedArtifact)
            .catch((err) => setError(err.message));
    }, [selectedKey]);

    useEffect(() => {
        if (
            !job?.job_id ||
            job.status === "completed" ||
            job.status === "failed"
        )
            return;
        const timer = setInterval(async () => {
            try {
                const updated = await fetchJson(`/api/jobs/${job.job_id}`);
                setJob(updated);
                if (updated.status === "completed") {
                    await refreshArtifacts();
                }
            } catch (err) {
                setError(err.message);
            }
        }, 2500);
        return () => clearInterval(timer);
    }, [job]);

    const summaryCards = useMemo(() => {
        if (!selectedArtifact) return [];
        const counts = selectedArtifact.summary?.counts || {};
        return [
            { label: "Packages", value: counts.packages ?? 0 },
            { label: "Vulnerabilities", value: counts.vulnerabilities ?? 0 },
            { label: "ATT&CK Techniques", value: counts.techniques ?? 0 },
        ];
    }, [selectedArtifact]);

    const sortedVulnerabilities = useMemo(() => {
        const vulnerabilities =
            selectedArtifact?.vulns?.vulnerabilities?.map((item, index) => ({
                ...item,
                originalIndex: index,
            })) || [];

        return [...vulnerabilities].sort((left, right) => {
            const severityDifference =
                getSeverityRank(left.severity) - getSeverityRank(right.severity);
            if (severityDifference !== 0) {
                return severityDifference;
            }

            const vulnIdComparison = String(left.vuln_id || "").localeCompare(
                String(right.vuln_id || ""),
            );
            if (vulnIdComparison !== 0) {
                return vulnIdComparison;
            }

            const packageComparison = String(
                left.package_name || "",
            ).localeCompare(String(right.package_name || ""));
            if (packageComparison !== 0) {
                return packageComparison;
            }

            return left.originalIndex - right.originalIndex;
        });
    }, [selectedArtifact]);

    async function submitScan(event) {
        event.preventDefault();
        setError("");
        setLoading(true);
        try {
            let data;
            if (scanMode === "tar") {
                if (!tarFile) {
                    throw new Error("Choose a tar file before running scan");
                }
                const formData = new FormData();
                formData.append("file", tarFile);
                formData.append("platform", platform);
                formData.append("short_len", "16");
                formData.append("skip_pull", "false");
                if (tarImageName.trim()) {
                    formData.append("image_name", tarImageName.trim());
                }

                const response = await fetch(`${API_BASE}/api/scans/upload`, {
                    method: "POST",
                    body: formData,
                });
                if (!response.ok) {
                    const text = await response.text();
                    throw new Error(
                        text || `Request failed: ${response.status}`,
                    );
                }
                data = await response.json();
            } else {
                data = await fetchJson("/api/scans", {
                    method: "POST",
                    body: JSON.stringify({
                        image,
                        platform,
                        short_len: 16,
                        skip_pull: false,
                    }),
                });
            }
            setJob(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    return (
        <main className="page-shell">
            <section className="hero">
                <div>
                    <p className="eyebrow">riskybisky</p>
                    <h1>
                        Scan containers, inspect risk, and browse ATT&CK output
                        in one portal.
                    </h1>
                </div>
                <form className="scan-card" onSubmit={submitScan}>
                    <label>
                        Input type
                        <div className="select-shell">
                            <select
                                value={scanMode}
                                onChange={(event) =>
                                    setScanMode(event.target.value)
                                }
                            >
                                <option value="image">Image reference</option>
                                <option value="tar">Local image tar</option>
                            </select>
                            <span className="select-arrow" aria-hidden="true">
                                ▾
                            </span>
                        </div>
                    </label>
                    {scanMode === "image" ? (
                        <label>
                            Image reference
                            <input
                                value={image}
                                onChange={(event) =>
                                    setImage(event.target.value)
                                }
                                placeholder="nginx:1.27-alpine"
                            />
                        </label>
                    ) : (
                        <>
                            <div className="form-field">
                                <span>Image tar file</span>
                                <div>
                                    <label className="file-picker">
                                        <input
                                            className="sr-only-file-input"
                                            type="file"
                                            accept=".tar,.tgz,.tar.gz"
                                            onChange={(event) =>
                                                setTarFile(
                                                    event.target.files?.[0] ||
                                                        null,
                                                )
                                            }
                                        />
                                        <span className="file-picker-button">
                                            Browse files
                                        </span>
                                        <span className="file-picker-value">
                                            {tarFile
                                                ? tarFile.name
                                                : "Select a local image tar"}
                                        </span>
                                    </label>
                                </div>
                            </div>
                            <label>
                                Image name in tar (optional)
                                <input
                                    value={tarImageName}
                                    onChange={(event) =>
                                        setTarImageName(event.target.value)
                                    }
                                    placeholder="repo/name:tag"
                                />
                            </label>
                        </>
                    )}
                    <label>
                        Platform
                        <input
                            value={platform}
                            onChange={(event) =>
                                setPlatform(event.target.value)
                            }
                            placeholder="linux/amd64"
                        />
                    </label>
                    <button type="submit" disabled={loading}>
                        {loading ? "Submitting..." : "Run Scan"}
                    </button>
                    {job && (
                        <p className="job-state">
                            Job {job.job_id} · {job.status} · {job.stage}
                        </p>
                    )}
                </form>
            </section>

            {error ? <div className="banner error">{error}</div> : null}

            <section className="content-grid">
                <aside className="panel list-panel">
                    <div className="panel-header">
                        <h2>Artifacts</h2>
                        <button
                            type="button"
                            onClick={() =>
                                refreshArtifacts().catch((err) =>
                                    setError(err.message),
                                )
                            }
                        >
                            Refresh
                        </button>
                    </div>
                    <div className="artifact-list">
                        {artifacts.map((artifact) => (
                            <button
                                key={artifact.artifact_key}
                                className={
                                    artifact.artifact_key === selectedKey
                                        ? "artifact-row active"
                                        : "artifact-row"
                                }
                                onClick={() =>
                                    setSelectedKey(artifact.artifact_key)
                                }
                            >
                                <strong>
                                    {artifact.image_input || "unknown image"}
                                </strong>
                                <span>{artifact.artifact_key}</span>
                            </button>
                        ))}
                    </div>
                </aside>

                <section className="panel detail-panel">
                    {selectedArtifact ? (
                        <>
                            <div className="panel-header">
                                <div>
                                    <h2>
                                        {selectedArtifact.summary.artifact_key}
                                    </h2>
                                    <p>
                                        {selectedArtifact.summary.image_input}
                                    </p>
                                </div>
                                <a
                                    href={`${API_BASE}/api/artifacts/${selectedArtifact.summary.artifact_key}/files/sbom.meta.json`}
                                    target="_blank"
                                    rel="noreferrer"
                                >
                                    Download meta
                                </a>
                            </div>

                            <div className="metrics-row">
                                {summaryCards.map((card) => (
                                    <article
                                        className="metric"
                                        key={card.label}
                                    >
                                        <span>{card.label}</span>
                                        <strong>{card.value}</strong>
                                    </article>
                                ))}
                            </div>

                            <div className="table-block">
                                <h3>Packages</h3>
                                <div className="table-scroll packages-scroll">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Name</th>
                                                <th>Version</th>
                                                <th>Type</th>
                                                <th>Depth</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {(
                                                selectedArtifact.packages
                                                    .packages || []
                                            ).map((pkg) => (
                                                <tr key={pkg.id}>
                                                    <td>{pkg.name}</td>
                                                    <td>
                                                        {pkg.version || "—"}
                                                    </td>
                                                    <td>{pkg.type}</td>
                                                    <td>
                                                        {pkg.dependency_depth}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>

                            <div className="table-block two-col">
                                <div>
                                    <h3>Vulnerabilities</h3>
                                    <div className="table-scroll summary-scroll">
                                        <table>
                                            <thead>
                                                <tr>
                                                    <th>ID</th>
                                                    <th>Severity</th>
                                                    <th>Package</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {sortedVulnerabilities.map(
                                                    (item, index) => (
                                                        <tr
                                                            key={`${item.vuln_id}-${index}`}
                                                        >
                                                            <td>
                                                                {item.vuln_id}
                                                            </td>
                                                            <td>
                                                                {item.severity}
                                                            </td>
                                                            <td>
                                                                {
                                                                    item.package_name
                                                                }
                                                            </td>
                                                        </tr>
                                                    ),
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div>
                                    <h3>ATT&CK Techniques</h3>
                                    <div className="table-scroll summary-scroll">
                                        <table>
                                            <thead>
                                                <tr>
                                                    <th>Technique</th>
                                                    <th>Priority</th>
                                                    <th>Risk</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {(
                                                    selectedArtifact
                                                        .attack_summary
                                                        .techniques || []
                                                ).map((item) => (
                                                    <tr
                                                        key={item.technique_id}
                                                    >
                                                        <td>
                                                            {
                                                                item.technique_id
                                                            }
                                                        </td>
                                                        <td>
                                                            {item.priority}
                                                        </td>
                                                        <td>
                                                            {
                                                                item.aggregate_risk
                                                            }
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="empty-state">
                            No artifact selected yet.
                        </div>
                    )}
                </section>
            </section>
        </main>
    );
}
