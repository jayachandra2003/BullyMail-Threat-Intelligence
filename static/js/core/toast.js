/**
 * BullyMail V2 — Cyber SOC Toast Notification System
 */
class SOCToast {
    static init() {
        if (!document.getElementById('socToastContainer')) {
            const container = document.createElement('div');
            container.id = 'socToastContainer';
            document.body.appendChild(container);
        }
    }

    static show(type = 'info', title = '', message = '', duration = 4500) {
        this.init();
        const container = document.getElementById('socToastContainer');
        
        const toast = document.createElement('div');
        toast.className = `soc-toast ${type}`;
        
        const icons = {
            success: 'fa-check-circle',
            warning: 'fa-exclamation-triangle',
            danger: 'fa-shield-virus',
            info: 'fa-info-circle'
        };

        const iconClass = icons[type] || icons.info;

        toast.innerHTML = `
            <div class="soc-toast-icon"><i class="fas ${iconClass}"></i></div>
            <div class="soc-toast-content">
                ${title ? `<div class="soc-toast-title">${title}</div>` : ''}
                <div class="soc-toast-msg">${message}</div>
            </div>
            <button class="soc-toast-close" aria-label="Close">&times;</button>
        `;

        toast.querySelector('.soc-toast-close').addEventListener('click', () => {
            this.dismiss(toast);
        });

        container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => {
                this.dismiss(toast);
            }, duration);
        }
    }

    static dismiss(toast) {
        if (!toast) return;
        toast.style.animation = 'toastSlideOut 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }

    static success(msg, title = 'Success') { this.show('success', title, msg); }
    static warning(msg, title = 'Warning') { this.show('warning', title, msg); }
    static error(msg, title = 'Error') { this.show('danger', title, msg); }
    static info(msg, title = 'Notice') { this.show('info', title, msg); }
}

window.SOCToast = SOCToast;
