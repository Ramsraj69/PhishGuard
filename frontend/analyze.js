const urlInput = document.getElementById("urlInput");
const analyzeButton = document.getElementById("analyzeButton");
const statusMessage = document.getElementById("statusMessage");

const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");

const securityVerdict = document.getElementById("securityVerdict");
const securityMessage = document.getElementById("securityMessage");

const httpsSignal = document.getElementById("httpsSignal");
const ipSignal = document.getElementById("ipSignal");
const reputationSignal = document.getElementById("reputationSignal");
const brandSignal = document.getElementById("brandSignal");
const redirectSignal = document.getElementById("redirectSignal");
const destinationSignal = document.getElementById("destinationSignal");

const riskReasons = document.getElementById("riskReasons");

const originalURL = document.getElementById("originalURL");
const finalURL = document.getElementById("finalURL");
const redirectCount = document.getElementById("redirectCount");
const domainChanged = document.getElementById("domainChanged");
const downgradeStatus = document.getElementById("downgradeStatus");

const recommendationTitle =
    document.getElementById("recommendationTitle");

const recommendationText =
    document.getElementById("recommendationText");


const API_URL = "http://127.0.0.1:5000/analyze";


analyzeButton.addEventListener("click", analyzeURL);


urlInput.addEventListener("keydown", function (event) {

    if (event.key === "Enter") {
        analyzeURL();
    }

});


async function analyzeURL() {

    const url = urlInput.value.trim();


    if (!url) {

        statusMessage.textContent =
            "Enter a URL before starting the investigation.";

        return;
    }


    setScanningState();


    try {

        const response = await fetch(API_URL, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });


        const data = await response.json();


        if (!response.ok) {

            throw new Error(
                data.error || "Analysis failed."
            );

        }


        displayAnalysis(data);


        statusMessage.textContent =
            "Investigation completed successfully.";


    } catch (error) {

        console.error(error);

        statusMessage.textContent =
            "Unable to reach the PhishGuard analysis engine.";

        resetAnalysis();

    } finally {

        analyzeButton.disabled = false;

        analyzeButton.innerHTML =
            `ANALYZE <span>→</span>`;

    }

}


/* =========================================================
   SCANNING STATE
   ========================================================= */

function setScanningState() {

    analyzeButton.disabled = true;

    analyzeButton.innerHTML =
        "SCANNING...";

    statusMessage.textContent =
        "PhishGuard is examining the URL and security signals...";

    riskScore.textContent = "...";

    riskLevel.textContent =
        "ANALYZING";

    securityVerdict.textContent =
        "Investigation in progress";

    securityMessage.textContent =
        "The detection engine is evaluating multiple security signals.";

}


/* =========================================================
   DISPLAY ANALYSIS
   ========================================================= */

function displayAnalysis(data) {

    const risk = data.risk_result;

    const redirects = data.redirect_analysis;

    const destination = data.destination_analysis;

    const downgrade = data.downgrade_analysis;

    const reputation = data.reputation_analysis;

    const brand = data.brand_analysis;


    /* -----------------------------------------
       RISK
       ----------------------------------------- */

    riskScore.textContent =
        risk.risk_score;

    riskLevel.textContent =
        risk.risk_level;


    /* -----------------------------------------
       VERDICT
       ----------------------------------------- */

    securityVerdict.textContent =
        getVerdict(risk.risk_level);

    securityMessage.textContent =
        getSecurityMessage(risk.risk_level);


    /* -----------------------------------------
       SIGNALS
       ----------------------------------------- */

    httpsSignal.textContent =
        data.https ? "SECURE" : "NOT SECURE";


    ipSignal.textContent =
        data.ip_address ? "DETECTED" : "NONE";


    reputationSignal.textContent =
        formatReputation(
            reputation.reputation_status
        );


    brandSignal.textContent =
        brand.impersonation
            ? "DETECTED"
            : "CLEAR";


    redirectSignal.textContent =
        redirects.redirect_count >= 0
            ? `${redirects.redirect_count}`
            : "UNAVAILABLE";


    destinationSignal.textContent =
        destination.domain_changed
            ? "CHANGED"
            : "UNCHANGED";


    /* -----------------------------------------
       REASONS
       ----------------------------------------- */

    displayReasons(
        risk.reasons
    );


    /* -----------------------------------------
       DESTINATION
       ----------------------------------------- */

    originalURL.textContent =
        destination.original_url || data.url;


    finalURL.textContent =
        redirects.final_url ||
        "Could not be reached safely";


    redirectCount.textContent =
        redirects.redirect_count >= 0
            ? redirects.redirect_count
            : "Unavailable";


    domainChanged.textContent =
    redirects.final_url
        ? (destination.domain_changed ? "YES" : "NO")
        : "UNAVAILABLE";

downgradeStatus.textContent =
    redirects.final_url
        ? (downgrade.downgrade ? "DETECTED" : "NONE")
        : "UNAVAILABLE";


    /* -----------------------------------------
       RECOMMENDATION
       ----------------------------------------- */

    displayRecommendation(
        risk.risk_level
    );

}


/* =========================================================
   VERDICT
   ========================================================= */

function getVerdict(level) {

    if (level === "HIGH") {

        return "High-risk destination detected";

    }

    if (level === "MEDIUM") {

        return "Suspicious characteristics detected";

    }

    return "No major threat indicators detected";

}


/* =========================================================
   SECURITY MESSAGE
   ========================================================= */

function getSecurityMessage(level) {

    if (level === "HIGH") {

        return "Multiple security indicators suggest that this URL should be avoided.";

    }

    if (level === "MEDIUM") {

        return "The URL contains characteristics that require additional caution.";

    }

    return "The current analysis found no major suspicious indicators.";

}


/* =========================================================
   REPUTATION
   ========================================================= */

function formatReputation(status) {

    if (status === "known_malicious") {
        return "MALICIOUS";
    }

    if (status === "unknown") {
        return "UNKNOWN";
    }

    return status
        ? status.toUpperCase()
        : "UNKNOWN";

}


/* =========================================================
   RISK REASONS
   ========================================================= */

function displayReasons(reasons) {

    riskReasons.innerHTML = "";


    if (!reasons || reasons.length === 0) {

        const item =
            document.createElement("li");

        item.textContent =
            "No major suspicious indicators were detected.";

        riskReasons.appendChild(item);

        return;
    }


    reasons.forEach(function (reason) {

        const item =
            document.createElement("li");

        item.textContent =
            reason;

        riskReasons.appendChild(item);

    });

}


/* =========================================================
   RECOMMENDATION
   ========================================================= */

function displayRecommendation(level) {

    if (level === "HIGH") {

        recommendationTitle.textContent =
            "Avoid opening this URL";

        recommendationText.textContent =
            "PhishGuard detected strong indicators associated with a potentially dangerous destination.";

        return;
    }


    if (level === "MEDIUM") {

        recommendationTitle.textContent =
            "Proceed with caution";

        recommendationText.textContent =
            "The URL contains suspicious characteristics. Verify the destination before continuing.";

        return;
    }


    recommendationTitle.textContent =
        "No major threat detected";

    recommendationText.textContent =
        "No major suspicious indicators were detected during the current analysis.";

}


/* =========================================================
   RESET
   ========================================================= */

function resetAnalysis() {

    riskScore.textContent = "--";

    riskLevel.textContent =
        "WAITING FOR ANALYSIS";

    securityVerdict.textContent =
        "No investigation performed";

    securityMessage.textContent =
        "Enter a URL above to begin a PhishGuard security investigation.";


    httpsSignal.textContent = "—";
    ipSignal.textContent = "—";
    reputationSignal.textContent = "—";
    brandSignal.textContent = "—";
    redirectSignal.textContent = "—";
    destinationSignal.textContent = "—";


    riskReasons.innerHTML =
        "<li>No investigation performed yet.</li>";


    originalURL.textContent = "—";
    finalURL.textContent = "—";
    redirectCount.textContent = "—";
    domainChanged.textContent = "—";
    downgradeStatus.textContent = "—";


    recommendationTitle.textContent =
        "Waiting for analysis";

    recommendationText.textContent =
        "Analyze a URL to receive a security recommendation.";

}