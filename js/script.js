/**
 * PHP FreeBase - Client Interactions
 * ----------------------------------
 * Lightweight, accessible interactions with zero third-party dependencies.
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Alert Dismissal with Smooth Transition
    document.querySelectorAll('.alert-close').forEach(button => {
        button.addEventListener('click', (e) => {
            const alert = e.target.closest('.alert');
            if (alert) {
                alert.style.transition = 'opacity 150ms ease, transform 150ms ease';
                alert.style.opacity = '0';
                alert.style.transform = 'scale(0.98)';
                setTimeout(() => alert.remove(), 160);
            }
        });
    });

    // 2. Prevent Double Submissions on Forms
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', (e) => {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.dataset.submitting) {
                submitBtn.dataset.submitting = 'true';
                // Add subtle opacity change while submitting
                submitBtn.style.opacity = '0.7';
                submitBtn.style.pointerEvents = 'none';
            }
        });
    });

    // 3. Escape Key Accessibility
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const openAlert = document.querySelector('.alert');
            if (openAlert) {
                openAlert.remove();
            }
        }
    });
});
