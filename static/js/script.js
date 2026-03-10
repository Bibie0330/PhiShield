// ===============================
// Risk Score Progress Bar
// ===============================
document.addEventListener("DOMContentLoaded", function () {
  const bars = document.querySelectorAll(".score-fill");
  bars.forEach(bar => {
    const score = bar.getAttribute("data-score");
    if (score !== null) {
      setTimeout(() => {
        bar.style.width = score + "%";
      }, 200);
    }
  });
});