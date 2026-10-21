// Farbschema: "auto" (Systemeinstellung), "light" oder "dark".
// Wird im <head> geladen, damit das gewählte Schema vor dem ersten Rendern gesetzt ist (kein Aufblitzen).
(function () {
    const STORAGE_KEY = 'theme';
    const ORDER = ['auto', 'light', 'dark'];
    const LABELS = { auto: '🌓 Auto', light: '☀️ Hell', dark: '🌙 Dunkel' };
    const NAMES = { auto: 'Automatisch (Systemeinstellung)', light: 'Hell', dark: 'Dunkel' };

    function readTheme() {
        try {
            const value = localStorage.getItem(STORAGE_KEY);
            return ORDER.includes(value) ? value : 'auto';
        } catch {
            return 'auto'; // localStorage kann blockiert sein (z. B. privater Modus)
        }
    }

    function applyTheme(theme) {
        if (theme === 'auto') {
            document.documentElement.removeAttribute('data-theme');
        } else {
            document.documentElement.setAttribute('data-theme', theme);
        }
    }

    let current = readTheme();
    applyTheme(current);

    document.addEventListener('DOMContentLoaded', () => {
        const button = document.getElementById('themeToggle');
        if (!button) return;

        function render() {
            const next = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
            button.textContent = LABELS[current];
            button.setAttribute('aria-label', `Farbschema: ${NAMES[current]}. Klicken für ${NAMES[next]}.`);
            button.title = `Farbschema: ${NAMES[current]}`;
        }

        button.addEventListener('click', () => {
            current = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
            applyTheme(current);
            try {
                if (current === 'auto') localStorage.removeItem(STORAGE_KEY);
                else localStorage.setItem(STORAGE_KEY, current);
            } catch {
                // Auswahl gilt dann nur für diese Sitzung
            }
            render();
        });
        render();
    });
})();
