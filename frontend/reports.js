const HISTORY_STORAGE_KEY = "phishguard_scan_history";


/* =========================================================
   REPORT ELEMENTS
========================================================= */

const reportTotal =
    document.getElementById("reportTotal");

const reportThreats =
    document.getElementById("reportThreats");

const reportSafe =
    document.getElementById("reportSafe");

const reportAverage =
    document.getElementById("reportAverage");


const lowRiskBar =
    document.getElementById("lowRiskBar");

const mediumRiskBar =
    document.getElementById("mediumRiskBar");

const highRiskBar =
    document.getElementById("highRiskBar");


const lowRiskCount =
    document.getElementById("lowRiskCount");

const mediumRiskCount =
    document.getElementById("mediumRiskCount");

const highRiskCount =
    document.getElementById("highRiskCount");


const summaryThreatRate =
    document.getElementById("summaryThreatRate");

const summaryHighestScore =
    document.getElementById("summaryHighestScore");

const summaryLowestScore =
    document.getElementById("summaryLowestScore");


const highestRiskContent =
    document.getElementById("highestRiskContent");

const reportEmpty =
    document.getElementById("reportEmpty");


const trendLine =
    document.getElementById("trendLine");

const trendEmpty =
    document.getElementById("trendEmpty");


/* =========================================================
   LOAD HISTORY
========================================================= */

function loadReportData() {

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
            "Unable to load report data:",
            error
        );

        history = [];

    }


    generateReport(history);

}


/* =========================================================
   GENERATE REPORT
========================================================= */

function generateReport(history) {

    if (history.length === 0) {

        showEmptyReport();

        return;

    }


    hideEmptyReport();


    const total =
        history.length;


    const threats =
        history.filter(function (scan) {

            return (
                scan.riskLevel === "MEDIUM" ||
                scan.riskLevel === "HIGH"
            );

        }).length;


    const safe =
        history.filter(function (scan) {

            return scan.riskLevel === "LOW";

        }).length;


    const scores =
        history
            .map(function (scan) {

                return Number(
                    scan.riskScore
                );

            })
            .filter(function (score) {

                return Number.isFinite(score);

            });


    let averageRisk = 0;


    if (scores.length > 0) {

        const totalRisk =
            scores.reduce(
                function (sum, score) {

                    return sum + score;

                },
                0
            );


        averageRisk =
            totalRisk / scores.length;

    }


    const highestScore =
        scores.length > 0
            ? Math.max(...scores)
            : 0;


    const lowestScore =
        scores.length > 0
            ? Math.min(...scores)
            : 0;


    const lowCount =
        history.filter(function (scan) {

            return scan.riskLevel === "LOW";

        }).length;


    const mediumCount =
        history.filter(function (scan) {

            return scan.riskLevel === "MEDIUM";

        }).length;


    const highCount =
        history.filter(function (scan) {

            return scan.riskLevel === "HIGH";

        }).length;


    /* =====================================================
       STATISTICS
    ===================================================== */

    reportTotal.textContent =
        total;


    reportThreats.textContent =
        threats;


    reportSafe.textContent =
        safe;


    reportAverage.textContent =
        `${averageRisk.toFixed(1)}`;


    /* =====================================================
       RISK DISTRIBUTION
    ===================================================== */

    lowRiskCount.textContent =
        lowCount;


    mediumRiskCount.textContent =
        mediumCount;


    highRiskCount.textContent =
        highCount;


    const lowPercentage =
        (lowCount / total) * 100;


    const mediumPercentage =
        (mediumCount / total) * 100;


    const highPercentage =
        (highCount / total) * 100;


    lowRiskBar.style.width =
        `${lowPercentage}%`;


    mediumRiskBar.style.width =
        `${mediumPercentage}%`;


    highRiskBar.style.width =
        `${highPercentage}%`;


    /* =====================================================
       SECURITY SUMMARY
    ===================================================== */

    const threatRate =
        (threats / total) * 100;


    summaryThreatRate.textContent =
        `${threatRate.toFixed(1)}%`;


    summaryHighestScore.textContent =
        `${highestScore}/100`;


    summaryLowestScore.textContent =
        `${lowestScore}/100`;


    /* =====================================================
       HIGHEST RISK INVESTIGATION
    ===================================================== */

    const highestRiskScan =
        history.reduce(
            function (highest, scan) {

                const currentScore =
                    Number(
                        scan.riskScore
                    );


                const highestScore =
                    Number(
                        highest.riskScore
                    );


                if (
                    !Number.isFinite(
                        highestScore
                    )
                ) {

                    return scan;

                }


                if (
                    Number.isFinite(
                        currentScore
                    ) &&
                    currentScore > highestScore
                ) {

                    return scan;

                }


                return highest;

            },
            history[0]
        );


    displayHighestRisk(
        highestRiskScan
    );


    /* =====================================================
       RISK TREND
    ===================================================== */

    displayRiskTrend(history);

}


/* =========================================================
   RISK TREND
========================================================= */

function displayRiskTrend(history) {

    if (!trendLine) {

        return;

    }


    /* Remove previous trend content */

    trendLine.innerHTML = "";


    const validScans =
        history.filter(function (scan) {

            return Number.isFinite(
                Number(scan.riskScore)
            );

        });


    if (validScans.length === 0) {

        const empty =
            document.createElement("div");

        empty.className =
            "trend-empty";

        empty.textContent =
            "No investigation data available yet.";

        trendLine.appendChild(
            empty
        );

        return;

    }


    /* =====================================================
       CHART DIMENSIONS
    ===================================================== */

    const width =
        Math.max(
            520,
            validScans.length * 90
        );


    const height =
        165;


    const padding =
        10;


    const usableWidth =
        width - (padding * 2);


    const usableHeight =
        height - (padding * 2);


    const maxScore =
        100;


    /* =====================================================
       BUILD POINTS
    ===================================================== */

    const points =
        validScans.map(
            function (scan, index) {

                const score =
                    Number(
                        scan.riskScore
                    );


                const x =
                    validScans.length === 1
                        ? width / 2
                        : padding +
                          (
                              index /
                              (validScans.length - 1)
                          ) *
                          usableWidth;


                const y =
                    padding +
                    (
                        1 -
                        (score / maxScore)
                    ) *
                    usableHeight;


                return {
                    x: x,
                    y: y,
                    score: score,
                    index: index
                };

            }
        );


    /* =====================================================
       SVG
    ===================================================== */

    const svg =
        document.createElementNS(
            "http://www.w3.org/2000/svg",
            "svg"
        );


    svg.setAttribute(
        "viewBox",
        `0 0 ${width} ${height}`
    );


    svg.setAttribute(
        "preserveAspectRatio",
        "none"
    );


    svg.classList.add(
        "trend-svg"
    );


    /* =====================================================
       LINE PATH
    ===================================================== */

    if (points.length > 1) {

        const path =
            document.createElementNS(
                "http://www.w3.org/2000/svg",
                "path"
            );


        let pathData =
            `M ${points[0].x} ${points[0].y}`;


        for (
            let index = 1;
            index < points.length;
            index++
        ) {

            pathData +=
                ` L ${points[index].x} ${points[index].y}`;

        }


        path.setAttribute(
            "d",
            pathData
        );


        path.classList.add(
            "trend-path"
        );


        svg.appendChild(
            path
        );

    }


    /* =====================================================
       POINTS
    ===================================================== */

    points.forEach(
        function (point) {

            const circle =
                document.createElementNS(
                    "http://www.w3.org/2000/svg",
                    "circle"
                );


            circle.setAttribute(
                "cx",
                point.x
            );


            circle.setAttribute(
                "cy",
                point.y
            );


            circle.setAttribute(
                "r",
                "5"
            );


            circle.classList.add(
                "trend-point"
            );


            svg.appendChild(
                circle
            );


            /* Score label */

            const scoreLabel =
                document.createElementNS(
                    "http://www.w3.org/2000/svg",
                    "text"
                );


            scoreLabel.setAttribute(
                "x",
                point.x
            );


            scoreLabel.setAttribute(
                "y",
                point.y - 10
            );


            scoreLabel.setAttribute(
                "text-anchor",
                "middle"
            );


            scoreLabel.setAttribute(
                "fill",
                "#c4ccd8"
            );


            scoreLabel.setAttribute(
                "font-size",
                "10"
            );


            scoreLabel.setAttribute(
                "font-weight",
                "700"
            );


            scoreLabel.textContent =
                point.score;


            svg.appendChild(
                scoreLabel
            );

        }
    );


    trendLine.appendChild(
        svg
    );


    /* =====================================================
       INVESTIGATION LABELS
    ===================================================== */

    points.forEach(
        function (point) {

            const label =
                document.createElement(
                    "div"
                );


            label.className =
                "trend-label";


            label.style.left =
                `${(point.x / width) * 100}%`;


            label.textContent =
                `SCAN ${point.index + 1}`;


            trendLine.appendChild(
                label
            );

        }
    );

}


/* =========================================================
   HIGHEST RISK DISPLAY
========================================================= */

function displayHighestRisk(scan) {

    if (!scan) {

        highestRiskContent.innerHTML = `
            <p>
                No investigation data available yet.
            </p>
        `;

        return;

    }


    const url =
        document.createElement("div");

    url.className =
        "highest-risk-url";

    url.textContent =
        scan.url || "Unknown URL";


    const score =
        document.createElement("div");

    score.className =
        "highest-risk-score";

    score.textContent =
        `RISK ${scan.riskScore}/100 • ${scan.riskLevel}`;


    highestRiskContent.innerHTML = "";


    highestRiskContent.appendChild(
        url
    );


    highestRiskContent.appendChild(
        score
    );

}


/* =========================================================
   EMPTY REPORT
========================================================= */

function showEmptyReport() {

    reportTotal.textContent =
        "0";


    reportThreats.textContent =
        "0";


    reportSafe.textContent =
        "0";


    reportAverage.textContent =
        "0";


    lowRiskCount.textContent =
        "0";


    mediumRiskCount.textContent =
        "0";


    highRiskCount.textContent =
        "0";


    lowRiskBar.style.width =
        "0%";


    mediumRiskBar.style.width =
        "0%";


    highRiskBar.style.width =
        "0%";


    summaryThreatRate.textContent =
        "0%";


    summaryHighestScore.textContent =
        "0/100";


    summaryLowestScore.textContent =
        "0/100";


    highestRiskContent.innerHTML = `
        <p>
            No investigation data available yet.
        </p>
    `;


    displayRiskTrend([]);


    if (reportEmpty) {

        reportEmpty.style.display =
            "block";

    }

}


/* =========================================================
   HIDE EMPTY REPORT
========================================================= */

function hideEmptyReport() {

    if (reportEmpty) {

        reportEmpty.style.display =
            "none";

    }

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

            loadReportData();

        }

    }
);


/* =========================================================
   START
========================================================= */

loadReportData();