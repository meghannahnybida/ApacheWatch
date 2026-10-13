// Apply the saved appearance before styles load to avoid a flash of the wrong theme.
(() => {
    const storageKey = 'apachewatch.theme';
    const choices = ['light', 'dark', 'system'];
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
    let preference = 'system';
    try {
        const saved = localStorage.getItem(storageKey);
        if (choices.includes(saved)) preference = saved;
    } catch { /* Appearance still works when browser storage is unavailable. */ }

    function apply() {
        const theme = preference === 'system' ? (systemTheme.matches ? 'dark' : 'light') : preference;
        document.documentElement.dataset.theme = theme;
        document.documentElement.dataset.themePreference = preference;
        document.dispatchEvent(new CustomEvent('apachewatch:themechange'));
    }

    window.ApacheWatchTheme = {
        getPreference: () => preference,
        setPreference(value) {
            if (!choices.includes(value)) return;
            preference = value;
            try { localStorage.setItem(storageKey, value); } catch { /* Keep the current tab usable. */ }
            apply();
        }
    };
    systemTheme.addEventListener('change', () => {
        if (preference === 'system') apply();
    });
    window.addEventListener('storage', event => {
        if (event.key !== storageKey && event.key !== null) return;
        preference = choices.includes(event.newValue) ? event.newValue : 'system';
        apply();
    });
    apply();
})();
