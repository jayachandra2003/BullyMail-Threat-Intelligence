/**
 * BullyMail V2 — 2-State Single-Click Theme Controller (Dark / Light)
 * Zero FOUC • Instant Single-Click Toggle • localStorage Persistence • Theme-Aware Charts
 */

class ThemeManager {
    static STORAGE_KEY = 'bullymail_theme';
    static DEFAULT_THEME = 'dark';

    static init() {
        this.applySavedTheme();

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initUI());
        } else {
            this.initUI();
        }
    }

    static getTheme() {
        const saved = localStorage.getItem(this.STORAGE_KEY);
        return (saved === 'light' || saved === 'dark') ? saved : this.DEFAULT_THEME;
    }

    static applySavedTheme() {
        const theme = this.getTheme();
        document.documentElement.setAttribute('data-theme', theme);
        document.documentElement.style.colorScheme = theme;
    }

    static toggleTheme() {
        const current = this.getTheme();
        const next = current === 'dark' ? 'light' : 'dark';
        this.setTheme(next);
    }

    static setTheme(theme) {
        localStorage.setItem(this.STORAGE_KEY, theme);
        document.documentElement.setAttribute('data-theme', theme);
        document.documentElement.style.colorScheme = theme;

        this.updateToggleButtons(theme);
        this.updateCharts(theme);

        window.dispatchEvent(new CustomEvent('socThemeChanged', {
            detail: { theme }
        }));
    }

    static initUI() {
        const theme = this.getTheme();
        this.updateToggleButtons(theme);

        // Bind all single-click theme toggle buttons on the page
        document.querySelectorAll('.soc-theme-toggle-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleTheme();
            });
        });
    }

    static updateToggleButtons(theme) {
        const isDark = theme === 'dark';
        const nextLabel = isDark ? 'Switch to light mode' : 'Switch to dark mode';
        const iconClass = isDark ? 'fas fa-sun' : 'fas fa-moon';

        document.querySelectorAll('.soc-theme-toggle-btn').forEach(btn => {
            btn.setAttribute('aria-label', nextLabel);
            btn.setAttribute('title', nextLabel);
            const icon = btn.querySelector('i');
            if (icon) {
                icon.className = iconClass;
            }
        });
    }

    static updateCharts(theme) {
        if (typeof Chart === 'undefined') return;

        const isDark = theme === 'dark';
        const textColor = isDark ? '#e2e8f0' : '#1e293b';
        const gridColor = isDark ? '#1e293b' : '#e2e8f0';

        Chart.defaults.color = textColor;
        Chart.defaults.borderColor = gridColor;

        if (typeof renderCharts === 'function') {
            renderCharts();
        }
    }
}

// Immediate execution to prevent flash of wrong theme
ThemeManager.applySavedTheme();
ThemeManager.init();

window.ThemeManager = ThemeManager;
