// ============================================================
// PHISHGUARD URL ANALYZER
// ============================================================


// ============================================================
// DOM ELEMENTS
// ============================================================

const urlInput =
    document.getElementById("urlInput");

const analyzeButton =
    document.getElementById("analyzeButton");

const statusMessage =
    document.getElementById("statusMessage");


// ============================================================
// RISK ELEMENTS
// ============================================================

const riskScore =
    document.getElementById("riskScore");

const riskLevel =
    document.getElementById("riskLevel");

const securityVerdict =
    document.getElementById("securityVerdict");

const securityMessage =
    document.getElementById("securityMessage");


// ============================================================
// ASSESSMENT STATUS
// ============================================================

const assessmentStatus =
    document.getElementById("assessmentStatus");


// ============================================================
// SECURITY SIGNALS
// ============================================================

const httpsSignal =
    document.getElementById("httpsSignal");

const ipSignal =
    document.getElementById("ipSignal");

const reputationSignal =
    document.getElementById("reputationSignal");

const brandSignal =
    document.getElementById("brandSignal");

const redirectSignal =
    document.getElementById("redirectSignal");

const destinationSignal =
    document.getElementById("destinationSignal");


// ============================================================
// EXPLAINABLE DETECTION
// ============================================================

const riskReasons =
    document.getElementById("riskReasons");


// ============================================================
// DESTINATION INTELLIGENCE
// ============================================================

const originalURL =
    document.getElementById("originalURL");

const finalURL =
    document.getElementById("finalURL");

const redirectCount =
    document.getElementById("redirectCount");

const domainChanged =
    document.getElementById("domainChanged");

const downgradeStatus =
    document.getElementById("downgradeStatus");


// ============================================================
// PROTECTION ENGINE
// ============================================================

const protectionActionPanel =
    document.getElementById("protectionActionPanel");

const protectionAction =
    document.getElementById("protectionAction");

const protectionMessage =
    document.getElementById("protectionMessage");

const protectionSeverity =
    document.getElementById("protectionSeverity");

const protectionStatusLabel =
    document.getElementById("protectionStatusLabel");


// ============================================================
// RECOMMENDATION
// ============================================================

const recommendationTitle =
    document.getElementById("recommendationTitle");

const recommendationText =
    document.getElementById("recommendationText");


// ============================================================
// SECURITY REPORT
// ============================================================

const generateReportButton =
    document.getElementById(
        "generateReportButton"
    );


// ============================================================
// CURRENT ANALYSIS DATA
// ============================================================

let currentAnalysisData = null;


// ============================================================
// HELPER FUNCTION
// ============================================================

function setText(element, value) {

    if (element) {

        element.textContent =
            value ?? "—";

    }

}


// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHTML(value) {

    const div =
        document.createElement("div");

    div.textContent =
        String(value ?? "");

    return div.innerHTML;

}


// ============================================================
// SCANNING STATE
// ============================================================

function setScanningState() {

    if (analyzeButton) {

        analyzeButton.disabled = true;

        analyzeButton.innerHTML =
            "SCANNING TARGET <span>⟳</span>";

    }


    if (statusMessage) {

        statusMessage.textContent =
            "Analyzing target. Please wait...";

    }


    setText(
        riskScore,
        "..."
    );


    setText(
        riskLevel,
        "ANALYZING"
    );


    setText(
        securityVerdict,
        "Investigation in progress"
    );


    setText(
        securityMessage,
        "PhishGuard is analyzing the target across multiple security layers."
    );


    if (assessmentStatus) {

        assessmentStatus.textContent =
            "ANALYZING TARGET";

    }


    setText(
        protectionAction,
        "ANALYZING"
    );


    setText(
        protectionMessage,
        "Protection decision will be generated after the investigation."
    );


    setText(
        protectionSeverity,
        "ANALYZING"
    );


    setText(
        protectionStatusLabel,
        "ANALYZING TARGET"
    );


    if (protectionActionPanel) {

        protectionActionPanel.classList.remove(
            "protection-allow",
            "protection-warn",
            "protection-block"
        );

    }


    if (generateReportButton) {

        generateReportButton.disabled = true;

    }

}


// ============================================================
// RESET ANALYSIS
// ============================================================

function resetAnalysis() {

    currentAnalysisData = null;


    setText(
        riskScore,
        "--"
    );


    setText(
        riskLevel,
        "WAITING"
    );


    setText(
        securityVerdict,
        "No investigation performed"
    );


    setText(
        securityMessage,
        "Enter a URL above to begin a PhishGuard security investigation."
    );


    if (assessmentStatus) {

        assessmentStatus.textContent =
            "AWAITING TARGET";

    }


    setText(
        httpsSignal,
        "—"
    );


    setText(
        ipSignal,
        "—"
    );


    setText(
        reputationSignal,
        "—"
    );


    setText(
        brandSignal,
        "—"
    );


    setText(
        redirectSignal,
        "—"
    );


    setText(
        destinationSignal,
        "—"
    );


    if (riskReasons) {

        riskReasons.innerHTML = `
            <li>
                No investigation performed yet.
            </li>
        `;

    }


    setText(
        originalURL,
        "—"
    );


    setText(
        finalURL,
        "—"
    );


    setText(
        redirectCount,
        "—"
    );


    setText(
        domainChanged,
        "—"
    );


    setText(
        downgradeStatus,
        "—"
    );


    setText(
        protectionAction,
        "WAITING"
    );


    setText(
        protectionMessage,
        "Analyze a URL to receive the PhishGuard protection decision."
    );


    setText(
        protectionSeverity,
        "—"
    );


    setText(
        protectionStatusLabel,
        "AWAITING ANALYSIS"
    );


    if (protectionActionPanel) {

        protectionActionPanel.classList.remove(
            "protection-allow",
            "protection-warn",
            "protection-block"
        );

    }


    setText(
        recommendationTitle,
        "Waiting for analysis"
    );


    setText(
        recommendationText,
        "Analyze a URL to receive a security recommendation."
    );


    if (generateReportButton) {

        generateReportButton.disabled = true;

    }


    if (analyzeButton) {

        analyzeButton.disabled = false;

        analyzeButton.innerHTML =
            "ANALYZE TARGET <span>→</span>";

    }

}


// ============================================================
// PROTECTION ACTION
// ============================================================

function displayProtectionAction(
    protection
) {

    if (!protection) {

        protection = {

            action: "WARN",

            severity: "UNKNOWN",

            message:
                "Protection decision unavailable."

        };

    }


    const action =
        String(
            protection.action || "WARN"
        ).toUpperCase();


    const severity =
        String(
            protection.severity || "UNKNOWN"
        ).toUpperCase();


    const message =
        protection.message ||
        "Protection decision unavailable.";


    setText(
        protectionAction,
        action
    );


    setText(
        protectionMessage,
        message
    );


    setText(
        protectionSeverity,
        severity
    );


    setText(
        protectionStatusLabel,
        "DECISION ACTIVE"
    );


    if (protectionActionPanel) {

        protectionActionPanel.classList.remove(
            "protection-allow",
            "protection-warn",
            "protection-block"
        );


        if (action === "ALLOW") {

            protectionActionPanel.classList.add(
                "protection-allow"
            );

        }


        else if (action === "WARN") {

            protectionActionPanel.classList.add(
                "protection-warn"
            );

        }


        else if (action === "BLOCK") {

            protectionActionPanel.classList.add(
                "protection-block"
            );

        }

    }

}


// ============================================================
// RISK REASONS
// ============================================================

function displayRiskReasons(
    riskResult
) {

    if (!riskReasons) {

        return;

    }


    riskReasons.innerHTML = "";


    const reasons =
        riskResult?.reasons || [];


    if (!reasons.length) {

        const li =
            document.createElement("li");

        li.textContent =
            "No major risk indicators were detected.";

        riskReasons.appendChild(li);

        return;

    }


    reasons.forEach(
        function(reason) {

            const li =
                document.createElement("li");

            li.textContent =
                reason;

            riskReasons.appendChild(li);

        }
    );

}


// ============================================================
// SECURITY SIGNALS
// ============================================================

function displaySecuritySignals(
    data
) {

    const analysis =
        data.analysis || {};

    const brand =
        data.brand_analysis || {};

    const reputation =
        data.reputation_analysis || {};

    const redirect =
        data.redirect_analysis || {};

    const destination =
        data.destination_analysis || {};


    if (analysis.https) {

        setText(
            httpsSignal,
            "SECURE"
        );

    }

    else {

        setText(
            httpsSignal,
            "NOT SECURE"
        );

    }


    if (analysis.ip_address) {

        setText(
            ipSignal,
            "DETECTED"
        );

    }

    else {

        setText(
            ipSignal,
            "NONE"
        );

    }


    if (
        reputation.reputation_status ===
        "known_malicious"
    ) {

        setText(
            reputationSignal,
            "MALICIOUS"
        );

    }

    else {

        setText(
            reputationSignal,
            "UNKNOWN"
        );

    }


    if (brand.impersonation) {

        setText(
            brandSignal,
            "DETECTED"
        );

    }

    else {

        setText(
            brandSignal,
            "NONE"
        );

    }


    const count =
        redirect.redirect_count || 0;


    if (count > 0) {

        setText(
            redirectSignal,
            `${count} HOP${count === 1 ? "" : "S"}`
        );

    }

    else {

        setText(
            redirectSignal,
            "NONE"
        );

    }


    if (destination.domain_changed) {

        setText(
            destinationSignal,
            "CHANGED"
        );

    }

    else {

        setText(
            destinationSignal,
            "UNCHANGED"
        );

    }

}


// ============================================================
// DESTINATION DISPLAY
// ============================================================

function displayDestination(
    data
) {

    const redirect =
        data.redirect_analysis || {};

    const destination =
        data.destination_analysis || {};


    setText(
        originalURL,
        data.url || "—"
    );


    setText(
        finalURL,
        redirect.final_url ||
        data.url ||
        "—"
    );


    setText(
        redirectCount,
        redirect.redirect_count ?? 0
    );


    setText(
        domainChanged,
        destination.domain_changed
            ? "YES"
            : "NO"
    );


    const downgrade =
        data.downgrade_analysis?.downgrade;


    setText(
        downgradeStatus,
        downgrade
            ? "DETECTED"
            : "NO"
    );

}


// ============================================================
// RECOMMENDATION
// ============================================================

function displayRecommendation(
    data
) {

    const protection =
        data.protection_result || {};

    const risk =
        data.risk_result || {};


    const action =
        String(
            protection.action || ""
        ).toUpperCase();


    if (action === "BLOCK") {

        setText(
            recommendationTitle,
            "BLOCK — Avoid opening this URL"
        );


        setText(
            recommendationText,
            protection.message ||
            "Strong threat indicators were detected."
        );

        return;

    }


    if (action === "WARN") {

        setText(
            recommendationTitle,
            "WARN — Verify before continuing"
        );


        setText(
            recommendationText,
            protection.message ||
            "Suspicious characteristics were detected."
        );

        return;

    }


    if (action === "ALLOW") {

        setText(
            recommendationTitle,
            "ALLOW — No major indicators detected"
        );


        setText(
            recommendationText,
            protection.message ||
            "No major threat indicators were detected."
        );

        return;

    }


    const level =
        String(
            risk.risk_level || ""
        ).toUpperCase();


    if (level === "HIGH") {

        setText(
            recommendationTitle,
            "BLOCK — Avoid opening this URL"
        );


        setText(
            recommendationText,
            "Multiple strong risk indicators were detected."
        );

    }

    else if (level === "MEDIUM") {

        setText(
            recommendationTitle,
            "WARN — Verify before continuing"
        );


        setText(
            recommendationText,
            "Suspicious characteristics were detected."
        );

    }

    else {

        setText(
            recommendationTitle,
            "ALLOW — No major indicators detected"
        );


        setText(
            recommendationText,
            "No major threat indicators were detected."
        );

    }

}


// ============================================================
// DISPLAY ANALYSIS
// ============================================================

function displayAnalysis(
    data
) {

    // --------------------------------------------------------
    // Reset scanning button after successful analysis
    // --------------------------------------------------------

    if (analyzeButton) {

        analyzeButton.disabled = false;

        analyzeButton.innerHTML =
            "ANALYZE TARGET <span>→</span>";

    }


    currentAnalysisData =
        data;


    const riskResult =
        data.risk_result || {};


    const score =
        riskResult.risk_score ?? 0;


    const level =
        riskResult.risk_level ||
        "LOW";


    setText(
        riskScore,
        score
    );


    setText(
        riskLevel,
        level
    );


    if (level === "HIGH") {

        setText(
            securityVerdict,
            "High-risk destination detected"
        );


        setText(
            securityMessage,
            "Multiple security indicators suggest that this URL should be avoided."
        );

    }

    else if (level === "MEDIUM") {

        setText(
            securityVerdict,
            "Suspicious destination detected"
        );


        setText(
            securityMessage,
            "Potentially suspicious characteristics were detected. Verify the destination before continuing."
        );

    }

    else {

        setText(
            securityVerdict,
            "Low-risk destination detected"
        );


        setText(
            securityMessage,
            "No major threat indicators were detected by the current PhishGuard analysis."
        );

    }


    if (assessmentStatus) {

        assessmentStatus.textContent =
            "TARGET ANALYZED";

    }


    displaySecuritySignals(
        data
    );


    displayRiskReasons(
        riskResult
    );


    displayDestination(
        data
    );


    const protection =
        data.protection_result || {};


    displayProtectionAction(
        protection
    );


    displayRecommendation(
        data
    );


    if (generateReportButton) {

        generateReportButton.disabled =
            false;

    }

}


// ============================================================
// SAVE SCAN HISTORY
// ============================================================

function saveScanHistory(
    data
) {

    try {

        const history =
            JSON.parse(
                localStorage.getItem(
                    "phishguard_history"
                ) || "[]"
            );


        const risk =
            data.risk_result || {};


        const protection =
            data.protection_result || {};


        const entry = {

            url:
                data.url || "",

            risk_score:
                risk.risk_score ?? 0,

            risk_level:
                risk.risk_level || "LOW",

            protection_action:
                protection.action || "WARN",

            protection_severity:
                protection.severity || "UNKNOWN",

            verdict:
                risk.risk_level === "HIGH"
                    ? "HIGH RISK"
                    : risk.risk_level === "MEDIUM"
                        ? "SUSPICIOUS"
                        : "LOW RISK",

            timestamp:
                new Date().toISOString()

        };


        history.unshift(
            entry
        );


        localStorage.setItem(
            "phishguard_history",
            JSON.stringify(
                history.slice(0, 50)
            )
        );

    }

    catch (error) {

        console.error(
            "Unable to save scan history:",
            error
        );

    }

}


// ============================================================
// SECURITY REPORT
// ============================================================

function generateSecurityReport() {

    if (!currentAnalysisData) {
        alert("Please analyze a URL before generating a report.");
        return;
    }

    const data = currentAnalysisData;

    const risk = data.risk_result || {};
    const protection = data.protection_result || {};
    const reputation = data.reputation_analysis || {};
    const redirect = data.redirect_analysis || {};
    const destination = data.destination_analysis || {};

    const reasons = Array.isArray(risk.reasons)
        ? risk.reasons
        : [];

    const reportWindow = window.open("", "_blank");

    if (!reportWindow) {
        alert(
            "The security report could not open. Please allow pop-ups for PhishGuard."
        );
        return;
    }

    const reasonsHTML = reasons.length > 0
        ? reasons.map(function (reason) {
            return `<li>${escapeHTML(reason)}</li>`;
        }).join("")
        : `<li>No major risk indicators detected.</li>`;

    const riskScore = risk.risk_score ?? 0;
    const riskLevel = risk.risk_level || "UNKNOWN";

    const action = protection.action || "WARN";
    const severity = protection.severity || "UNKNOWN";

    const protectionMessage =
        protection.message ||
        "Protection decision unavailable.";

    const reputationStatus =
        reputation.reputation_status ||
        "unknown";

    const redirectCount =
        redirect.redirect_count ?? 0;

    const finalURL =
        redirect.final_url ||
        data.url ||
        "—";

    const domainChanged =
        destination.domain_changed
            ? "YES"
            : "NO";

    const downgrade =
        data.downgrade_analysis &&
        data.downgrade_analysis.downgrade
            ? "DETECTED"
            : "NO";

    const reportDate =
        new Date().toLocaleString();


    const reportHTML = `

        <style>

            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                padding: 40px 20px;
                background: #07101a;
                color: #e5edf7;
                font-family: Arial, Helvetica, sans-serif;
            }

            .report-container {
                width: 100%;
                max-width: 950px;
                margin: 0 auto;
            }

            .header {
                padding-bottom: 25px;
                margin-bottom: 25px;
                border-bottom: 1px solid #26374a;
            }

            .logo {
                color: #4ade80;
                font-size: 30px;
                font-weight: 900;
                letter-spacing: 0.04em;
            }

            .subtitle {
                margin-top: 7px;
                color: #7f91a7;
                font-size: 13px;
            }

            .section {
                margin-bottom: 20px;
                padding: 24px;
                background: #0b1623;
                border: 1px solid #1d2a3a;
                border-radius: 15px;
            }

            .section h2 {
                margin: 0 0 18px;
                color: #7dd3fc;
                font-size: 12px;
                letter-spacing: 0.12em;
            }

            .grid {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 15px;
            }

            .item {
                min-width: 0;
                padding: 15px;
                background: #07101a;
                border: 1px solid #182738;
                border-radius: 10px;
            }

            .item small {
                display: block;
                margin-bottom: 7px;
                color: #64748b;
                font-size: 9px;
                font-weight: 800;
                letter-spacing: 0.10em;
            }

            .item strong {
                display: block;
                color: #e5edf7;
                font-size: 14px;
                line-height: 1.5;
                word-break: break-word;
            }

            .score {
                color: #f87171;
                font-size: 42px;
                font-weight: 900;
            }

            .level {
                font-size: 24px;
                font-weight: 900;
            }

            .action {
                color: #f87171;
                font-size: 30px;
                font-weight: 900;
                margin-bottom: 8px;
            }

            .message {
                color: #aab8c8;
                line-height: 1.6;
            }

            ul {
                margin: 0;
                padding-left: 22px;
            }

            li {
                margin-bottom: 10px;
                color: #aab8c8;
                line-height: 1.5;
            }

            .footer {
                margin-top: 30px;
                padding-top: 18px;
                border-top: 1px solid #26374a;
                color: #52657a;
                font-size: 11px;
                line-height: 1.6;
            }

            @media (max-width: 650px) {

                body {
                    padding: 25px 12px;
                }

                .grid {
                    grid-template-columns: 1fr;
                }

                .section {
                    padding: 18px;
                }

            }

        </style>


        <div class="report-container">

            <div class="header">

                <div class="logo">
                    🛡️ PHISHGUARD
                </div>

                <div class="subtitle">
                    Security Intelligence Investigation Report
                </div>

            </div>


            <!-- INVESTIGATION -->

            <div class="section">

                <h2>INVESTIGATION</h2>

                <div class="grid">

                    <div class="item">

                        <small>TARGET URL</small>

                        <strong>
                            ${escapeHTML(data.url || "—")}
                        </strong>

                    </div>

                    <div class="item">

                        <small>SCAN TIME</small>

                        <strong>
                            ${escapeHTML(reportDate)}
                        </strong>

                    </div>

                </div>

            </div>


            <!-- RISK -->

            <div class="section">

                <h2>RISK ASSESSMENT</h2>

                <div class="grid">

                    <div class="item">

                        <small>RISK SCORE</small>

                        <div class="score">
                            ${escapeHTML(String(riskScore))}/100
                        </div>

                    </div>

                    <div class="item">

                        <small>RISK LEVEL</small>

                        <div class="level">
                            ${escapeHTML(riskLevel)}
                        </div>

                    </div>

                </div>

            </div>


            <!-- PROTECTION -->

            <div class="section">

                <h2>PROTECTION DECISION</h2>

                <div class="action">
                    ${escapeHTML(action)}
                </div>

                <div class="message">
                    ${escapeHTML(protectionMessage)}
                </div>

                <br>

                <strong>
                    Severity:
                    ${escapeHTML(severity)}
                </strong>

            </div>


            <!-- DETECTION -->

            <div class="section">

                <h2>DETECTION FINDINGS</h2>

                <ul>
                    ${reasonsHTML}
                </ul>

            </div>


            <!-- NETWORK -->

            <div class="section">

                <h2>
                    NETWORK &amp; DESTINATION INTELLIGENCE
                </h2>

                <div class="grid">

                    <div class="item">

                        <small>REPUTATION</small>

                        <strong>
                            ${escapeHTML(reputationStatus)}
                        </strong>

                    </div>

                    <div class="item">

                        <small>REDIRECT COUNT</small>

                        <strong>
                            ${escapeHTML(String(redirectCount))}
                        </strong>

                    </div>

                    <div class="item">

                        <small>FINAL DESTINATION</small>

                        <strong>
                            ${escapeHTML(finalURL)}
                        </strong>

                    </div>

                    <div class="item">

                        <small>DOMAIN CHANGED</small>

                        <strong>
                            ${escapeHTML(domainChanged)}
                        </strong>

                    </div>

                    <div class="item">

                        <small>HTTPS DOWNGRADE</small>

                        <strong>
                            ${escapeHTML(downgrade)}
                        </strong>

                    </div>

                </div>

            </div>


            <div class="footer">

                Generated by PhishGuard Security Intelligence Platform.

                <br>

                CyberClash 2026.

            </div>

        </div>
    `;


    // --------------------------------------------------------
    // Render directly into the new window
    // --------------------------------------------------------

    reportWindow.document.title =
        "PhishGuard Security Report";

    reportWindow.document.body.innerHTML =
        reportHTML;

    reportWindow.focus();
}


        // ----------------------------------------------------
        // Protection values
        // ----------------------------------------------------

        const action =
            protection.action ||
            "WARN";


        const severity =
            protection.severity ||
            "UNKNOWN";


        const protectionText =
            protection.message ||
            "Protection decision unavailable.";


        // ----------------------------------------------------
        // Reputation
        // ----------------------------------------------------

        const reputationStatus =
            reputation.reputation_status ||
            "unknown";


        // ----------------------------------------------------
        // Redirect count
        // ----------------------------------------------------

        const redirects =
            redirect.redirect_count ?? 0;


        // ----------------------------------------------------
        // Final destination
        // ----------------------------------------------------

        const destinationURL =
            redirect.final_url ||
            data.url ||
            "—";


        // ----------------------------------------------------
        // Domain change
        // ----------------------------------------------------

        const changed =
            destination.domain_changed
                ? "YES"
                : "NO";


        // ----------------------------------------------------
        // HTTPS downgrade
        // ----------------------------------------------------

        const downgrade =
            data.downgrade_analysis?.downgrade
                ? "DETECTED"
                : "NO";


        // ----------------------------------------------------
        // Report HTML
        // ----------------------------------------------------

        const reportHTML = `

<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
PhishGuard Security Report
</title>


<style>

* {
    box-sizing: border-box;
}


body {

    margin: 0;

    padding: 40px 20px;

    background:
        #07101a;

    color:
        #e5edf7;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

}


.container {

    width: 100%;

    max-width: 950px;

    margin: 0 auto;

}


.header {

    padding-bottom: 25px;

    margin-bottom: 25px;

    border-bottom:
        1px solid #26374a;

}


.logo {

    color:
        #4ade80;

    font-size:
        30px;

    font-weight:
        900;

    letter-spacing:
        0.04em;

}


.subtitle {

    margin-top: 7px;

    color:
        #7f91a7;

    font-size:
        13px;

}


.section {

    margin-bottom: 20px;

    padding: 24px;

    background:
        #0b1623;

    border:
        1px solid #1d2a3a;

    border-radius:
        15px;

}


.section h2 {

    margin:
        0 0 18px;

    color:
        #7dd3fc;

    font-size:
        12px;

    letter-spacing:
        0.12em;

}


.grid {

    display:
        grid;

    grid-template-columns:
        repeat(2, minmax(0, 1fr));

    gap:
        15px;

}


.item {

    min-width:
        0;

    padding:
        15px;

    background:
        #07101a;

    border:
        1px solid #182738;

    border-radius:
        10px;

}


.item small {

    display:
        block;

    margin-bottom:
        7px;

    color:
        #64748b;

    font-size:
        9px;

    font-weight:
        800;

    letter-spacing:
        0.10em;

}


.item strong {

    display:
        block;

    color:
        #e5edf7;

    font-size:
        14px;

    line-height:
        1.5;

    word-break:
        break-word;

}


.score {

    color:
        #f87171;

    font-size:
        42px;

    font-weight:
        900;

}


.level {

    font-size:
        24px;

    font-weight:
        900;

}


.action {

    color:
        #f87171;

    font-size:
        30px;

    font-weight:
        900;

    margin-bottom:
        8px;

}


.message {

    color:
        #aab8c8;

    line-height:
        1.6;

}


ul {

    margin:
        0;

    padding-left:
        22px;

}


li {

    margin-bottom:
        10px;

    color:
        #aab8c8;

    line-height:
        1.5;

}


.footer {

    margin-top:
        30px;

    padding-top:
        18px;

    border-top:
        1px solid #26374a;

    color:
        #52657a;

    font-size:
        11px;

    line-height:
        1.6;

}


@media (max-width: 650px) {

    body {

        padding:
            25px 12px;

    }


    .grid {

        grid-template-columns:
            1fr;

    }


    .section {

        padding:
            18px;

    }

}

</style>

</head>


<body>


<div class="container">


    <div class="header">

        <div class="logo">
            🛡️ PHISHGUARD
        </div>


        <div class="subtitle">
            Security Intelligence Investigation Report
        </div>

    </div>


    <!-- INVESTIGATION -->

    <div class="section">

        <h2>
            INVESTIGATION
        </h2>


        <div class="grid">

            <div class="item">

                <small>
                    TARGET URL
                </small>


                <strong>
                    ${escapeHTML(data.url || "—")}
                </strong>

            </div>


            <div class="item">

                <small>
                    SCAN TIME
                </small>


                <strong>
                    ${escapeHTML(reportDate)}
                </strong>

            </div>

        </div>

    </div>


    <!-- RISK -->

    <div class="section">

        <h2>
            RISK ASSESSMENT
        </h2>


        <div class="grid">

            <div class="item">

                <small>
                    RISK SCORE
                </small>


                <div class="score">
                    ${escapeHTML(
                        String(
                            risk.risk_score ?? 0
                        )
                    )}/100
                </div>

            </div>


            <div class="item">

                <small>
                    RISK LEVEL
                </small>


                <div class="level">

                    ${escapeHTML(
                        risk.risk_level ||
                        "UNKNOWN"
                    )}

                </div>

            </div>

        </div>

    </div>


    <!-- PROTECTION -->

    <div class="section">

        <h2>
            PROTECTION DECISION
        </h2>


        <div class="action">

            ${escapeHTML(action)}

        </div>


        <div class="message">

            ${escapeHTML(protectionText)}

        </div>


        <br>


        <strong>

            Severity:
            ${escapeHTML(severity)}

        </strong>

    </div>


    <!-- DETECTION -->

    <div class="section">

        <h2>
            DETECTION FINDINGS
        </h2>


        <ul>

            ${reasonsHTML}

        </ul>

    </div>


    <!-- NETWORK -->

    <div class="section">

        <h2>
            NETWORK &amp; DESTINATION INTELLIGENCE
        </h2>


        <div class="grid">


            <div class="item">

                <small>
                    REPUTATION
                </small>


                <strong>
                    ${escapeHTML(
                        reputationStatus
                    )}
                </strong>

            </div>


            <div class="item">

                <small>
                    REDIRECT COUNT
                </small>


                <strong>
                    ${escapeHTML(
                        String(redirects)
                    )}
                </strong>

            </div>


            <div class="item">

                <small>
                    FINAL DESTINATION
                </small>


                <strong>
                    ${escapeHTML(
                        destinationURL
                    )}
                </strong>

            </div>


            <div class="item">

                <small>
                    DOMAIN CHANGED
                </small>


                <strong>
                    ${escapeHTML(changed)}
                </strong>

            </div>


            <div class="item">

                <small>
                    HTTPS DOWNGRADE
                </small>


                <strong>
                    ${escapeHTML(downgrade)}
                </strong>

            </div>


        </div>

    </div>


    <div class="footer">

        Generated by PhishGuard Security Intelligence Platform.

        <br>

        CyberClash 2026.

    </div>


</div>


</body>

</html>

        `;


        // ----------------------------------------------------
// Load report using a Blob URL
// ----------------------------------------------------

const reportBlob =
    new Blob(
        [reportHTML],
        {
            type: "text/html"
        }
    );


const reportURL =
    URL.createObjectURL(
        reportBlob
    );


reportWindow.location.href =
    reportURL;


// ----------------------------------------------------
// Focus report window
// ----------------------------------------------------

reportWindow.focus();


// ----------------------------------------------------
// Release Blob URL after loading
// ----------------------------------------------------

setTimeout(
    function() {

        URL.revokeObjectURL(
            reportURL
        );

    },
    5000
);

    }

    catch (error) {

        console.error(
            "Security report generation error:",
            error
        );


        reportWindow.document.open();


        reportWindow.document.write(`

            <!DOCTYPE html>

            <html>

            <head>

                <title>
                    PhishGuard Report Error
                </title>

                <style>

                    body {

                        background: #07101a;

                        color: #e5edf7;

                        font-family: Arial;

                        padding: 40px;

                    }

                    h1 {

                        color: #f87171;

                    }

                </style>

            </head>


            <body>

                <h1>
                    Report Generation Error
                </h1>


                <p>
                    PhishGuard could not generate the
                    investigation report.
                </p>


                <p>
                    Please return to the analyzer and
                    run the investigation again.
                </p>

            </body>

            </html>

        `);


        reportWindow.document.close();

    }

}


// ============================================================
// ANALYZE URL
// ============================================================

async function analyzeURL() {

    const url =
        urlInput?.value.trim();


    if (!url) {

        if (statusMessage) {

            statusMessage.textContent =
                "Please enter a URL before starting the investigation.";

        }

        return;

    }


    setScanningState();


    try {

        const response =
            await fetch(
                "http://127.0.0.1:5000/analyze",
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body:
                        JSON.stringify({
                            url: url
                        })

                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            throw new Error(
                data.error ||
                "Server returned an error."
            );

        }


        displayAnalysis(
            data
        );


        saveScanHistory(
            data
        );


        if (statusMessage) {

            statusMessage.textContent =
                "Investigation completed successfully.";

        }

    }

    catch (error) {

        console.error(
            "PhishGuard analysis error:",
            error
        );


        if (statusMessage) {

            statusMessage.textContent =
                "Investigation failed: " +
                error.message;

        }


        resetAnalysis();

    }

}


// ============================================================
// BUTTON EVENTS
// ============================================================

if (analyzeButton) {

    analyzeButton.addEventListener(
        "click",
        analyzeURL
    );

}


// ============================================================
// ENTER KEY SUPPORT
// ============================================================

if (urlInput) {

    urlInput.addEventListener(
        "keydown",
        function(event) {

            if (
                event.key === "Enter" &&
                !analyzeButton.disabled
            ) {

                analyzeURL();

            }

        }
    );

}


// ============================================================
// REPORT BUTTON
// ============================================================

if (generateReportButton) {

    generateReportButton.addEventListener(
        "click",
        generateSecurityReport
    );

}


// ============================================================
// INITIAL STATE
// ============================================================

resetAnalysis();