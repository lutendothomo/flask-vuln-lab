/**
 * NARI Logistics - Enterprise Client Script
 */

document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss flash messages after 6 seconds
  const flashAlerts = document.querySelectorAll('.flash-messages .alert');
  flashAlerts.forEach(alert => {
    setTimeout(() => {
      alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
      alert.style.opacity = '0';
      alert.style.transform = 'translateY(-8px)';
      setTimeout(() => alert.remove(), 500);
    }, 6000);
  });

  
  initTheme();
});

/**
 * Dark & Light Theme Controller
 */
function initTheme() {
  const saved = localStorage.getItem('nari-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('nari-theme', next);
}

/**
 * Toggle Create Booking Form Panel
 */
function toggleCreateModal() {
  const panel = document.getElementById('create-booking-panel');
  if (!panel) return;

  if (panel.style.display === 'block') {
    panel.style.display = 'none';
  } else {
    panel.style.display = 'block';
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    const clientInput = document.getElementById('client_name');
    if (clientInput) clientInput.focus();
  }
}

/**
 * Handle Edit Button Click using data-* attributes
 */
function handleEditClick(btn) {
  if (!btn) return;
  const id = btn.getAttribute('data-id');
  const client = btn.getAttribute('data-client');
  const pickup = btn.getAttribute('data-pickup');
  const delivery = btn.getAttribute('data-delivery');
  const notes = btn.getAttribute('data-notes');
  openEditModal(id, client, pickup, delivery, notes);
}

/**
 * Open Edit Shipment Modal
 */
function openEditModal(bookingId, clientName, pickup, delivery, notes) {
  const modal = document.getElementById('edit-modal-overlay');
  const form = document.getElementById('edit-booking-form');
  const title = document.getElementById('edit-modal-title');

  if (!modal || !form) return;

  form.action = `/bookings/${bookingId}/edit`;
  if (title) title.textContent = `Edit Shipment #TRK-${String(bookingId).padStart(4, '0')}`;

  document.getElementById('edit_client_name').value = clientName || '';
  document.getElementById('edit_pickup_location').value = pickup || '';
  document.getElementById('edit_delivery_location').value = delivery || '';
  document.getElementById('edit_notes').value = notes || '';

  modal.classList.add('active');
}

/**
 * Close Edit Shipment Modal
 */
function closeEditModal() {
  const modal = document.getElementById('edit-modal-overlay');
  if (modal) modal.classList.remove('active');
}

/**
 * Close modal when clicking on overlay background or pressing Escape
 */
document.addEventListener('click', (e) => {
  const modal = document.getElementById('edit-modal-overlay');
  if (modal && e.target === modal) {
    closeEditModal();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeEditModal();
  }
});

/**
 * Toggle Password Visibility
 */
function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;

  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';

  if (btn) {
    btn.innerHTML = isPassword
      ? `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`
      : `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  }
}

/**
 * Real-time Password Strength Validator on Register
 */
function validatePasswordStrength(pw) {
  const check = (id, valid) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (valid) {
      el.classList.add('valid');
      el.querySelector('.req-icon').innerHTML = '✓';
    } else {
      el.classList.remove('valid');
      el.querySelector('.req-icon').innerHTML = '&bull;';
    }
  };

  check('req-length', pw.length >= 5 && pw.length <= 64);
  check('req-upper', /[A-Z]/.test(pw));
  check('req-lower', /[a-z]/.test(pw));
  check('req-num', /\d/.test(pw));
  check('req-special', /[^A-Za-z0-9\s]/.test(pw));
  check('req-nospace', pw.length > 0 && !/\s/.test(pw));
}

/**
 * Copy Tracking Code to Clipboard
 */
function copyTrackingCode(code) {
  navigator.clipboard.writeText(code).then(() => {
    alert(`Copied tracking reference #${code} to clipboard!`);
  }).catch(() => {
    prompt('Copy tracking code:', code);
  });
}
