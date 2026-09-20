const HISTORY_STORAGE_KEY = "phishguard_scan_history";


const historyList = document.getElementById("historyList");
const totalScans = document.getElementById("totalScans");
const threatScans = document.getElementById("threatScans");
const safeScans = document.getElementById("safeScans");
const historyCount = document.getElementById("historyCount");
const clearHistoryButton =
    document.getElementById("clearHistoryButton");


/* =========================================================
   LOAD HISTORY
   ========================================================= */

function loadHistory() {

    let history = [];

    try {

        const storedHistory =
            localStorage.getItem(
                HISTORY_STORAGE_KEY
            );

        if (storedHistory) {

            history =
                JSON.parse(storedHistory);

        }

        if (!Array.isArray(history)) {

            history = [];

        }

    } catch (error) {

        console.error(
            "Unable to load scan history:",
            error
        );

        history = [];

    }


    updateStatistics(history);

    displayHistory(history);

}


/* =========================================================
   UPDATE STATISTICS
   ========================================================= */

function updateStatistics(history) {

    const total = history.length;


    const threats = history.filter(function (scan) {

        return (
            scan.riskLevel === "MEDIUM" ||
            scan.riskLevel === "HIGH"
        );

    }).length;


    const safe = history.filter(function (scan) {

        return scan.riskLevel === "LOW";

    }).length;


    totalScans.textContent = total;

    threatScans.textContent = threats;

    safeScans.textContent = safe;

    historyCount.textContent =
        `${total} SCANS`;

}


/* =========================================================
   DISPLAY HISTORY
   ========================================================= */

function displayHistory(history) {

    historyList.innerHTML = "";


    if (history.length === 0) {

        historyList.innerHTML = `
            <div class="empty-activity">

                <div class="empty-icon">
                    ◷
                </div>

                <strong>
                    No investigations yet
                </strong>

                <p>
                    Your analyzed URLs will appear here.
                </p>

                <a href="analyze.html">
                    Run your first scan →
                </a>

            </div>
        `;

        return;

    }


    history.forEach(function (scan) {

        const row =
            document.createElement("div");

        row.className =
            "history-row";


        /* -----------------------------------------
           URL
           ----------------------------------------- */

        const urlCell =
            document.createElement("div");

        urlCell.className =
            "history-url";

        urlCell.textContent =
            scan.url;


        /* -----------------------------------------
           RISK SCORE
           ----------------------------------------- */

        const riskCell =
            document.createElement("div");

        riskCell.className =
            "history-risk";

        riskCell.textContent =
            `${scan.riskScore}/100`;


        /* -----------------------------------------
           RISK STATUS
           ----------------------------------------- */

        const statusCell =
            document.createElement("div");

        statusCell.className =
            "history-status";

        statusCell.textContent =
            scan.riskLevel;


        applyRiskStyle(
            statusCell,
            scan.riskLevel
        );


        /* -----------------------------------------
           TIME
           ----------------------------------------- */

        const timeCell =
            document.createElement("div");

        timeCell.className =
            "history-time";

        timeCell.textContent =
            formatTimestamp(
                scan.timestamp
            );


        /* -----------------------------------------
           BUILD ROW
           ----------------------------------------- */

        row.appendChild(urlCell);

        row.appendChild(riskCell);

        row.appendChild(statusCell);

        row.appendChild(timeCell);


        historyList.appendChild(row);

    });

}


/* =========================================================
   RISK STATUS STYLE
   ========================================================= */

function applyRiskStyle(element, level) {

    const normalizedLevel =
        String(level || "")
            .toUpperCase();


    if (normalizedLevel === "HIGH") {

        element.style.background =
            "rgba(255, 70, 70, 0.14)";

        element.style.border =
            "1px solid rgba(255, 70, 70, 0.35)";

        element.style.color =
            "#ff6b6b";

        return;

    }


    if (normalizedLevel === "MEDIUM") {

        element.style.background =
            "rgba(255, 180, 70, 0.14)";

        element.style.border =
            "1px solid rgba(255, 180, 70, 0.35)";

        element.style.color =
            "#ffbd66";

        return;

    }


    element.style.background =
        "rgba(70, 220, 140, 0.14)";

    element.style.border =
        "1px solid rgba(70, 220, 140, 0.35)";

    element.style.color =
        "#66e0a0";

}


/* =========================================================
   FORMAT TIMESTAMP
   ========================================================= */

function formatTimestamp(timestamp) {

    if (!timestamp) {

        return "Unknown";

    }


    const date =
        new Date(timestamp);


    if (Number.isNaN(date.getTime())) {

        return "Unknown";

    }


    return date.toLocaleString(
        undefined,
        {
            dateStyle: "medium",
            timeStyle: "short"
        }
    );

}


/* =========================================================
   CLEAR HISTORY
   ========================================================= */

clearHistoryButton.addEventListener(
    "click",
    function () {

        const confirmed =
            confirm(
                "Are you sure you want to clear all scan history?"
            );


        if (!confirmed) {

            return;

        }


        localStorage.removeItem(
            HISTORY_STORAGE_KEY
        );


        loadHistory();

    }
);


/* =========================================================
   START
   ========================================================= */

loadHistory();