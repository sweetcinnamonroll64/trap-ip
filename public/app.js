// ── IP Tracker — runs silently on page load ────────────────────────────────
(async function () {
  try {
    await fetch('/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        path: window.location.pathname,
        hostname: window.location.hostname,
      }),
    });
  } catch (_) {
    // Silent fail — tracking should never break the page
  }
})();

// ── Signup form ────────────────────────────────────────────────────────────
const form = document.getElementById('signup-form');
if (form) {
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const btn = document.getElementById('signup-btn');
    const input = document.getElementById('email-input');
    btn.textContent = '✓ You\'re on the list!';
    btn.style.background = 'linear-gradient(135deg, #059669, #10b981)';
    input.disabled = true;
    btn.disabled = true;
  });
}

// ── Scroll reveal animation ────────────────────────────────────────────────
const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.style.animation = 'fadeUp 0.6s ease forwards';
        observer.unobserve(entry.target);
      }
    });
  },
  { threshold: 0.1 }
);

document.querySelectorAll('.card, .about-text, .about-visual').forEach((el) => {
  el.style.opacity = '0';
  observer.observe(el);
});
