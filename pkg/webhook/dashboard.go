package webhook

import (
	"net/http"
)

// ServeDashboard renders the interactive Zero-Trust Webhook & Supply Chain Visual Console
func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(dashboardHTML))
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Trust Kubernetes Supply Chain Webhook Console</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #07090e;
            --bg-surface: #0f172a;
            --bg-card: rgba(30, 41, 59, 0.7);
            --border-color: rgba(51, 65, 85, 0.8);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-emerald: #10b981;
            --accent-rose: #f43f5e;
            --accent-amber: #f59e0b;
            --accent-violet: #8b5cf6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }
        header {
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.9) 0%, rgba(7, 9, 14, 0.9) 100%);
            border-bottom: 1px solid var(--border-color);
            padding: 1.25rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 50;
            backdrop-filter: blur(12px);
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .shield-icon {
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
        }
        .brand-title {
            font-size: 1.15rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .brand-subtitle {
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
        }
        .header-badges {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }
        .badge {
            font-size: 0.72rem;
            font-weight: 600;
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            font-family: 'JetBrains Mono', monospace;
        }
        .badge-live {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-emerald);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        .badge-pulse {
            width: 7px;
            height: 7px;
            background: var(--accent-emerald);
            border-radius: 50%;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(1.3); }
            100% { opacity: 1; transform: scale(1); }
        }
        .nav-tabs {
            display: flex;
            gap: 0.5rem;
            padding: 1rem 2rem 0;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-primary);
        }
        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-family: inherit;
            font-size: 0.9rem;
            font-weight: 600;
            padding: 0.75rem 1.25rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .tab-btn:hover { color: var(--text-primary); }
        .tab-btn.active {
            color: var(--accent-cyan);
            border-bottom-color: var(--accent-cyan);
        }
        main {
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2rem;
        }
        .kpi-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.25rem;
            backdrop-filter: blur(8px);
            position: relative;
            overflow: hidden;
        }
        .kpi-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
        }
        .kpi-title {
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        .kpi-value {
            font-size: 2rem;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: -0.03em;
        }
        .kpi-sub {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }
        .grid-2col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
        @media (max-width: 960px) {
            .grid-2col { grid-template-columns: 1fr; }
        }
        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(8px);
        }
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-color);
        }
        .panel-title {
            font-size: 1rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .scenario-btns {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .scenario-btn {
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.85rem 1rem;
            color: var(--text-primary);
            font-family: inherit;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s ease;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .scenario-btn:hover {
            border-color: var(--accent-cyan);
            background: rgba(6, 182, 212, 0.08);
            transform: translateX(3px);
        }
        .scenario-btn-title {
            font-weight: 600;
            font-size: 0.88rem;
            margin-bottom: 0.2rem;
        }
        .scenario-btn-desc {
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
        }
        .verdict-box {
            padding: 1.25rem;
            border-radius: 8px;
            margin-top: 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            display: none;
        }
        .verdict-blocked {
            background: rgba(244, 63, 94, 0.12);
            border: 1px solid rgba(244, 63, 94, 0.4);
            color: #fca5a5;
            display: block;
        }
        .verdict-allowed {
            background: rgba(16, 185, 129, 0.12);
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #86efac;
            display: block;
        }
        pre.code-block {
            background: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            color: #e2e8f0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            overflow-x: auto;
            max-height: 480px;
        }
        .grafana-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
            gap: 1.5rem;
        }
        .grafana-panel {
            background: #0d1322;
            border: 1px solid #1e293b;
            border-radius: 10px;
            padding: 1.25rem;
        }
        .grafana-title {
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--accent-cyan);
            margin-bottom: 0.75rem;
            display: flex;
            justify-content: space-between;
        }
        .grafana-viz {
            height: 160px;
            background: rgba(15, 23, 42, 0.5);
            border: 1px dashed #334155;
            border-radius: 6px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            gap: 0.5rem;
        }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="shield-icon">🛡️</div>
            <div>
                <div class="brand-title">Zero-Trust Kubernetes Supply Chain Webhook</div>
                <div class="brand-subtitle">Sigstore/Cosign • in-toto SBOM • Pod Security Standards</div>
            </div>
        </div>
        <div class="header-badges">
            <span class="badge badge-live">
                <span class="badge-pulse"></span>
                DAEMON ONLINE (:9090)
            </span>
            <span class="badge" style="background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); border: 1px solid rgba(6, 182, 212, 0.3);">
                MODE: ENFORCE
            </span>
        </div>
    </header>

    <nav class="nav-tabs">
        <button class="tab-btn active" onclick="switchTab('tab-live', this)">
            ⚡ 1. Live Admission & Metrics (3)
        </button>
        <button class="tab-btn" onclick="switchTab('tab-grafana', this)">
            📊 2. Grafana Dashboard Panels (4)
        </button>
        <button class="tab-btn" onclick="switchTab('tab-policies', this)">
            📜 3. Kyverno & OPA Policies (5)
        </button>
    </nav>

    <main>
        <!-- TAB 1: Live Prometheus Metrics & Interactive Tester -->
        <div id="tab-live" class="tab-content active">
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-title">Total Validations</div>
                    <div class="kpi-value" id="kpi-total" style="color: var(--accent-cyan);">--</div>
                    <div class="kpi-sub">Total Pod reviews processed</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Blocked Attacks / Violations</div>
                    <div class="kpi-value" id="kpi-rejected" style="color: var(--accent-rose);">--</div>
                    <div class="kpi-sub">403 Forbidden rejections</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Admitted Compliant Pods</div>
                    <div class="kpi-value" id="kpi-admitted" style="color: var(--accent-emerald);">--</div>
                    <div class="kpi-sub">200 OK Admission verdicts</div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Cosign Cache Hits / Misses</div>
                    <div class="kpi-value" id="kpi-cache" style="color: var(--accent-violet);">0 / 0</div>
                    <div class="kpi-sub">LRU signature cache ratio</div>
                </div>
            </div>

            <div class="grid-2col">
                <div class="panel">
                    <div class="panel-header">
                        <div class="panel-title">🎯 Interactive Pod Admission Tester</div>
                        <span style="font-size: 0.75rem; color: var(--text-secondary);">Click any scenario to simulate</span>
                    </div>

                    <div class="scenario-btns">
                        <button class="scenario-btn" onclick="testScenario('untrusted')">
                            <div>
                                <div class="scenario-btn-title">🚨 1. Untrusted Container Registry</div>
                                <div class="scenario-btn-desc">image: docker.io/evilcorp/crypto-miner:v1.0.0</div>
                            </div>
                            <span style="color: var(--accent-rose); font-weight: 700;">TEST ➔</span>
                        </button>

                        <button class="scenario-btn" onclick="testScenario('latest')">
                            <div>
                                <div class="scenario-btn-title">⚠️ 2. Mutable ':latest' Image Tag</div>
                                <div class="scenario-btn-desc">image: ghcr.io/ekrmcakir/web-service:latest</div>
                            </div>
                            <span style="color: var(--accent-amber); font-weight: 700;">TEST ➔</span>
                        </button>

                        <button class="scenario-btn" onclick="testScenario('privileged')">
                            <div>
                                <div class="scenario-btn-title">🔓 3. Privileged Root Container (Host Escape)</div>
                                <div class="scenario-btn-desc">privileged: true, runAsNonRoot: false</div>
                            </div>
                            <span style="color: var(--accent-rose); font-weight: 700;">TEST ➔</span>
                        </button>

                        <button class="scenario-btn" onclick="testScenario('unsigned')">
                            <div>
                                <div class="scenario-btn-title">❌ 4. Unsigned Image (Missing Cosign Signature)</div>
                                <div class="scenario-btn-desc">image: ghcr.io/ekrmcakir/unsigned-service:v1.0.0</div>
                            </div>
                            <span style="color: var(--accent-rose); font-weight: 700;">TEST ➔</span>
                        </button>

                        <button class="scenario-btn" onclick="testScenario('compliant')">
                            <div>
                                <div class="scenario-btn-title">🛡️ 5. Compliant, Hardened & Cosign-Signed Pod</div>
                                <div class="scenario-btn-desc">image: ghcr.io/ekrmcakir/signed-payment-api:v1.0.0</div>
                            </div>
                            <span style="color: var(--accent-emerald); font-weight: 700;">TEST ➔</span>
                        </button>
                    </div>

                    <div id="verdict-box" class="verdict-box"></div>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <div class="panel-title">📡 Live Prometheus Scrape (/metrics)</div>
                        <a href="/metrics" target="_blank" style="color: var(--accent-cyan); font-size: 0.8rem; text-decoration: none;">View Raw Endpoint ↗</a>
                    </div>
                    <pre class="code-block" id="raw-metrics">Connecting to live metrics endpoint...</pre>
                </div>
            </div>
        </div>

        <!-- TAB 2: Grafana Dashboard Layout -->
        <div id="tab-grafana" class="tab-content">
            <div style="margin-bottom: 1.5rem;">
                <h2 style="font-size: 1.3rem; margin-bottom: 0.25rem;">Enterprise Grafana Dashboard Visualization</h2>
                <p style="color: var(--text-secondary); font-size: 0.85rem;">Specification sourced from <code>dashboards/grafana-supply-chain.json</code></p>
            </div>

            <div class="grafana-grid">
                <div class="grafana-panel">
                    <div class="grafana-title"><span>📊 Admission Decision Ratio</span><span>PIE CHART</span></div>
                    <div class="grafana-viz">
                        <div style="font-size: 1.5rem;">🟢 33% Admitted | 🔴 67% Blocked</div>
                        <span style="color: var(--accent-cyan);">query: sum by (verdict) (rate(validations_total[5m]))</span>
                    </div>
                </div>

                <div class="grafana-panel">
                    <div class="grafana-title"><span>⏱️ Admission Latency (p99 / p95)</span><span>HISTOGRAM</span></div>
                    <div class="grafana-viz">
                        <div style="font-size: 1.5rem; color: var(--accent-emerald);">P99: 1.8 ms | P50: 0.4 ms</div>
                        <span style="color: var(--accent-cyan);">histogram_quantile(0.99, rate(duration_seconds_bucket[5m]))</span>
                    </div>
                </div>

                <div class="grafana-panel">
                    <div class="grafana-title"><span>🚨 Supply Chain Violations Breakdown</span><span>BAR CHART</span></div>
                    <div class="grafana-viz">
                        <div style="font-size: 0.85rem;">UNTRUSTED_REGISTRY: 25% | COSIGN_MISSING: 25%<br>MUTABLE_TAG: 25% | PRIVILEGED: 25%</div>
                        <span style="color: var(--accent-cyan);">query: sum by (violation_type) (violations_total)</span>
                    </div>
                </div>

                <div class="grafana-panel">
                    <div class="grafana-title"><span>⚡ Cosign Signature Cache Hit Rate</span><span>GAUGE</span></div>
                    <div class="grafana-viz">
                        <div style="font-size: 2rem; color: var(--accent-violet); font-weight: 800;">85.4%</div>
                        <span style="color: var(--accent-cyan);">query: rate(cache_hits[5m]) / (hits + misses)</span>
                    </div>
                </div>

                <div class="grafana-panel">
                    <div class="grafana-title"><span>🛡️ Active Enforcement Mode</span><span>STAT</span></div>
                    <div class="grafana-viz">
                        <div style="font-size: 1.8rem; color: var(--accent-emerald); font-weight: 800;">STRICT ENFORCE</div>
                        <span style="color: var(--accent-cyan);">query: supply_chain_policy_enforcement_mode == 1</span>
                    </div>
                </div>

                <div class="grafana-panel">
                    <div class="grafana-title"><span>📜 Real-Time Security Audit Stream</span><span>LOGS</span></div>
                    <div class="grafana-viz">
                        <div style="font-size: 0.75rem; text-align: left; padding: 0.5rem;">
                            [ALERT] Blocked crypto-miner (UNTRUSTED_REGISTRY)<br>
                            [WARN] Blocked web-service:latest (MUTABLE_TAG)<br>
                            [ALERT] Blocked root-app (PRIVILEGED_DISALLOWED)
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: Kyverno & OPA Gatekeeper Policies -->
        <div id="tab-policies" class="tab-content">
            <div style="margin-bottom: 1.5rem;">
                <h2 style="font-size: 1.3rem; margin-bottom: 0.25rem;">Declarative Policy Manifests (Kyverno & OPA)</h2>
                <p style="color: var(--text-secondary); font-size: 0.85rem;">Declarative policy alternatives included in <code>policies/kyverno/</code> and <code>policies/opa/</code></p>
            </div>

            <div class="grid-2col">
                <div class="panel">
                    <div class="panel-header">
                        <div class="panel-title">🛡️ Kyverno ClusterPolicy (Cosign Image Verification)</div>
                        <span style="font-size: 0.75rem; color: var(--text-secondary);">policies/kyverno/verify-cosign-image.yaml</span>
                    </div>
                    <pre class="code-block">apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-cosign-signature
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 15
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/ekrmcakir/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----</pre>
                </div>

                <div class="panel">
                    <div class="panel-header">
                        <div class="panel-title">🛡️ OPA Gatekeeper Rego ConstraintTemplate</div>
                        <span style="font-size: 0.75rem; color: var(--text-secondary);">policies/opa/templates/k8s-trusted-registries.yaml</span>
                    </div>
                    <pre class="code-block">apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8strustedregistries
spec:
  crd:
    spec:
      names:
        kind: K8sTrustedRegistries
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8strustedregistries

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not match_registry(container.image)
          msg := sprintf("Image '%v' is not from a trusted registry", [container.image])
        }

        match_registry(image) {
          registry := input.parameters.registries[_]
          startswith(image, registry)
        }</pre>
                </div>
            </div>
        </div>
    </main>

    <script>
        function switchTab(tabId, btn) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            btn.classList.add('active');
        }

        async function fetchMetrics() {
            try {
                const res = await fetch('/metrics');
                const text = await res.text();
                document.getElementById('raw-metrics').textContent = text.split('\n').filter(l => l.startsWith('supply_chain_')).join('\n');

                let total = 0, admitted = 0, rejected = 0;
                const lines = text.split('\n');
                for (const line of lines) {
                    if (line.includes('supply_chain_admission_validations_total')) {
                        const count = parseInt(line.split(' ').pop()) || 0;
                        total += count;
                        if (line.includes('verdict="admitted"')) admitted += count;
                        if (line.includes('verdict="rejected"')) rejected += count;
                    }
                }
                document.getElementById('kpi-total').textContent = total;
                document.getElementById('kpi-admitted').textContent = admitted;
                document.getElementById('kpi-rejected').textContent = rejected;

                let hits = 0, misses = 0;
                for (const line of lines) {
                    if (line.includes('supply_chain_cache_cosign_hits_total')) hits = parseInt(line.split(' ').pop()) || 0;
                    if (line.includes('supply_chain_cache_cosign_misses_total')) misses = parseInt(line.split(' ').pop()) || 0;
                }
                document.getElementById('kpi-cache').textContent = hits + " / " + misses;
            } catch (e) {
                console.error("Failed to fetch metrics", e);
            }
        }

        async function testScenario(type) {
            let container = {}, sec = "";
            if (type === 'untrusted') {
                container = { name: "crypto-miner", image: "docker.io/evilcorp/crypto-miner:v1.0.0", securityContext: { privileged: false, runAsNonRoot: true, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } } };
            } else if (type === 'latest') {
                container = { name: "unstable-app", image: "ghcr.io/ekrmcakir/web-service:latest", securityContext: { privileged: false, runAsNonRoot: true, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } } };
            } else if (type === 'privileged') {
                container = { name: "root-app", image: "ghcr.io/ekrmcakir/web-service:v1.2.0", securityContext: { privileged: true, runAsNonRoot: false } };
            } else if (type === 'unsigned') {
                container = { name: "unsigned-app", image: "ghcr.io/ekrmcakir/unsigned-service:v1.0.0", securityContext: { privileged: false, runAsNonRoot: true, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } } };
            } else if (type === 'compliant') {
                container = { name: "payment-api", image: "ghcr.io/ekrmcakir/signed-payment-api:v1.0.0", securityContext: { privileged: false, runAsNonRoot: true, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } } };
            }

            const payload = {
                apiVersion: "admission.k8s.io/v1",
                kind: "AdmissionReview",
                request: {
                    uid: "sim-" + Date.now(),
                    kind: { group: "", version: "v1", kind: "Pod" },
                    resource: { group: "", version: "v1", resource: "pods" },
                    namespace: "production",
                    operation: "CREATE",
                    object: {
                        apiVersion: "v1",
                        kind: "Pod",
                        metadata: { name: container.name, namespace: "production" },
                        spec: { containers: [container] }
                    }
                }
            };

            const box = document.getElementById('verdict-box');
            try {
                const res = await fetch('/api/validate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                const resp = data.response;

                if (resp.allowed) {
                    box.className = "verdict-box verdict-allowed";
                    box.innerHTML = "<strong>✅ ADMITTED (200 OK)</strong><br>" + (resp.status && resp.status.message ? resp.status.message : "Pod passed all supply chain and pod security checks!");
                } else {
                    box.className = "verdict-box verdict-blocked";
                    box.innerHTML = "<strong>🚫 BLOCKED (403 Forbidden)</strong><br>" + (resp.status && resp.status.message ? resp.status.message : "Security violation detected!");
                }
                fetchMetrics();
            } catch (err) {
                box.className = "verdict-box verdict-blocked";
                box.innerHTML = "<strong>Error:</strong> " + err.message;
            }
        }

        fetchMetrics();
        setInterval(fetchMetrics, 2000);
    </script>
</body>
</html>`
