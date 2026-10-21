
const messageBox = document.getElementById("message");
const charCount = document.getElementById("char-count");
const clearButton = document.getElementById("clear-message");
const form = document.getElementById("analyze-form");
const analyzeButton = form?.querySelector('button[type="submit"]');

function updateCounter() {
    if (!messageBox || !charCount) return;

    charCount.textContent = `${messageBox.value.length} / 10000`;
}

messageBox?.addEventListener("input", updateCounter);
updateCounter();

clearButton?.addEventListener("click", () => {
    if (!messageBox) return;

    messageBox.value = "";
    updateCounter();
    messageBox.focus();
});

form?.addEventListener("submit", (event) => {
    if (!messageBox?.value.trim()) {
        event.preventDefault();
        messageBox?.focus();
        return;
    }

    if (analyzeButton) {
        analyzeButton.disabled = true;
        const buttonText = analyzeButton.querySelector("span");

        if (buttonText) {
            buttonText.textContent = "Analyzing message...";
        }
    }
});
