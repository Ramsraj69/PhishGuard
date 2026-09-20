const HISTORY_STORAGE_KEY = "phishguard_scan_history";


/* =========================================================
   DASHBOARD ELEMENTS
   ========================================================= */

const statCards =
    document.querySelectorAll(".stats-grid .stat-card");

const activityTable =
    document.querySelector(".activity-table");


/* =========================================================
   LOAD DASHBOARD DATA
   ========================================================= */

function loadDashboardData() {

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
            "Unable to load dashboard history:",
            error
        );

        history = [];

    }


    updateDashboardStatistics(history);

    updateRecentActivity(history);

}


/* =========================================================
   UPDATE STATISTICS
   ========================================================= */

function updateDashboardStatistics(history) {

    if (!statCards || statCards.length < 4) {

        return;

    }


    const totalScans =
        history.length;


    const threatsDetected =
        history.filter(function (scan) {

            return (
                scan.riskLevel === "MEDIUM" ||
                scan.riskLevel === "HIGH"
            );

        }).length;


    const safeAnalyses =
        history.filter(function (scan) {

            return scan.riskLevel === "LOW";

        }).length;


    const totalElement =
        statCards[0].querySelector("strong");


    if (totalElement) {

        totalElement.textContent =
            totalScans;

    }


    const threatElement =
        statCards[1].querySelector("strong");


    if (threatElement) {

        threatElement.textContent =
            threatsDetected;

    }


    const safeElement =
        statCards[2].querySelector("strong");


    if (safeElement) {

        safeElement.textContent =
            safeAnalyses;

    }

}


/* =========================================================
   UPDATE RECENT ACTIVITY
   ========================================================= */

function updateRecentActivity(history) {

    if (!activityTable) {

        return;

    }


    const oldEmptyState =
        activityTable.querySelector(
            ".empty-activity"
        );


    if (oldEmptyState) {

        oldEmptyState.remove();

    }


    const existingRows =
        activityTable.querySelectorAll(
            ".dashboard-history-row"
        );


    existingRows.forEach(function (row) {

        row.remove();

    });


    if (history.length === 0) {

        showEmptyActivity();

        return;

    }


    /*
       Display the five newest investigations.
    */

    const recentScans =
        history.slice(0, 5);


    recentScans.forEach(function (scan) {

        const row =
            document.createElement("div");


        row.className =
            "dashboard-history-row";


        /* =================================================
           ROW LAYOUT
           ================================================= */

        row.style.display =
            "grid";

        row.style.gridTemplateColumns =
            "minmax(0, 1fr) 90px 110px 150px";

        row.style.alignItems =
            "center";

        row.style.gap =
            "18px";

        row.style.padding =
            "18px 24px";

        row.style.borderBottom =
            "1px solid rgba(255, 255, 255, 0.06)";

        row.style.width =
            "100%";

        row.style.boxSizing =
            "border-box";


        /* =================================================
           URL
           ================================================= */

        const urlCell =
            document.createElement("span");


        urlCell.textContent =
            scan.url;


        urlCell.title =
            scan.url;


        urlCell.style.display =
            "block";

        urlCell.style.minWidth =
            "0";

        urlCell.style.overflow =
            "hidden";

        urlCell.style.textOverflow =
            "ellipsis";

        urlCell.style.whiteSpace =
            "nowrap";

        urlCell.style.fontSize =
            "13px";


        /* =================================================
           RISK SCORE
           ================================================= */

        const riskCell =
            document.createElement("span");


        riskCell.textContent =
            `${scan.riskScore}/100`;


        riskCell.style.fontWeight =
            "700";

        riskCell.style.textAlign =
            "center";


        /* =================================================
           STATUS
           ================================================= */

        const statusCell =
            document.createElement("span");


        statusCell.textContent =
            scan.riskLevel;


        statusCell.style.display =
            "inline-flex";

        statusCell.style.justifyContent =
            "center";

        statusCell.style.alignItems =
            "center";

        statusCell.style.minWidth =
            "75px";

        statusCell.style.padding =
            "6px 10px";

        statusCell.style.borderRadius =
            "4px";

        statusCell.style.fontSize =
            "11px";

        statusCell.style.fontWeight =
            "700";

        statusCell.style.letterSpacing =
            "0.08em";


        applyRiskStyle(
            statusCell,
            scan.riskLevel
        );


        /* =================================================
           ACTION
           ================================================= */

        const actionCell =
            document.createElement("span");


        actionCell.textContent =
            "VIEW HISTORY →";


        actionCell.style.fontSize =
            "11px";

        actionCell.style.fontWeight =
            "700";

        actionCell.style.letterSpacing =
            "0.06em";

        actionCell.style.cursor =
            "pointer";

        actionCell.style.whiteSpace =
            "nowrap";


        actionCell.addEventListener(
            "click",
            function () {

                window.location.href =
                    "history.html";

            }
        );


        /* =================================================
           BUILD ROW
           ================================================= */

        row.appendChild(urlCell);

        row.appendChild(riskCell);

        row.appendChild(statusCell);

        row.appendChild(actionCell);


        activityTable.appendChild(row);

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
   EMPTY ACTIVITY STATE
   ========================================================= */

function showEmptyActivity() {

    const emptyState =
        document.createElement("div");


    emptyState.className =
        "empty-activity";


    emptyState.innerHTML = `

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

    `;


    activityTable.appendChild(
        emptyState
    );

}


/* =========================================================
   LIVE UPDATE
   ========================================================= */

window.addEventListener(
    "storage",
    function (event) {

        if (
            event.key === HISTORY_STORAGE_KEY
        ) {

            loadDashboardData();

        }

    }
);


/* =========================================================
   START DASHBOARD
   ========================================================= */

loadDashboardData();