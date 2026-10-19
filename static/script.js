
const messageBox = document.getElementById("message");
const charCount = document.getElementById("char-count");
const clearButton = document.getElementById("clear-message");
const form = document.querySelector("form");
const analyzeButton = form?.querySelector('button[type="submit"]');

function updateCounter() {
    if (messageBox && charCount) {
        charCount.textContent =
            `${messageBox.value.length} / 10000 characters`;
    }
}

messageBox?.addEventListener("input", updateCounter);
updateCounter();

clearButton?.addEventListener("click", () => {
    if (messageBox) {
        messageBox.value = "";
        updateCounter();
        messageBox.focus();
    }
});

form?.addEventListener("submit", (event) => {
    if (!messageBox?.value.trim()) {
        event.preventDefault();
        messageBox?.focus();
        return;
    }

    if (analyzeButton) {
        analyzeButton.textContent = "Analyzing...";
        analyzeButton.disabled = true;
    }
});
