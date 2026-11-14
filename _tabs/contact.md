---
icon: fas fa-envelope
order: 5
title: Contact
---

<div class="contact-wrap">

  <p class="contact-intro">
    Have a question, opportunity, or just want to connect? Send a message below —
    I'll get it directly in my inbox and reply as soon as I can.
  </p>

  <form id="contact-form" class="contact-form" action="https://formspree.io/f/xbgodbpg" method="POST">

    <div class="form-group">
      <label for="cf-name">Name</label>
      <input type="text" id="cf-name" name="name" required placeholder="Your full name" />
    </div>

    <div class="form-group">
      <label for="cf-email">Email</label>
      <input type="email" id="cf-email" name="email" required
             pattern="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
             placeholder="you@company.com" />
      <small class="field-hint">Must be a valid email address (e.g. name@company.com)</small>
    </div>

    <div class="form-group">
      <label for="cf-message">Message</label>
      <textarea id="cf-message" name="message" rows="6" required placeholder="Write your message here..."></textarea>
    </div>

    <!-- honeypot field - invisible to humans, bots fill it in and get silently rejected -->
    <input type="text" name="_gotcha" style="display:none" tabindex="-1" autocomplete="off" />

    <button type="submit" class="contact-submit">
      <i class="fas fa-paper-plane"></i> Send Message
    </button>

    <p id="contact-status" class="contact-status"></p>

  </form>

</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('contact-form');
  const status = document.getElementById('contact-status');

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    status.textContent = 'Sending...';
    status.className = 'contact-status sending';

    fetch(form.action, {
      method: 'POST',
      body: new FormData(form),
      headers: { 'Accept': 'application/json' }
    })
    .then(response => {
      if (response.ok) {
        status.textContent = '✓ Message sent — thanks for reaching out!';
        status.className = 'contact-status success';
        form.reset();
      } else {
        response.json().then(data => {
          if (data.errors) {
            status.textContent = data.errors.map(e => e.message).join(', ');
          } else {
            status.textContent = 'Something went wrong. Please try again or email me directly.';
          }
          status.className = 'contact-status error';
        });
      }
    })
    .catch(() => {
      status.textContent = 'Something went wrong. Please try again or email me directly.';
      status.className = 'contact-status error';
    });
  });
});
</script>

<style>
.contact-wrap {
  max-width: 560px;
  margin: 1rem auto 0;
}

.contact-intro {
  font-size: .95rem;
  color: var(--text-color);
  margin-bottom: 1.75rem;
  line-height: 1.6;
}

.contact-form {
  display: flex;
  flex-direction: column;
  gap: 1.1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: .4rem;
}

.form-group label {
  font-size: .85rem;
  font-weight: 600;
  color: var(--heading-color);
}

.form-group input,
.form-group textarea {
  padding: .65rem .85rem;
  border: 1px solid var(--border-color);
  border-radius: 8px;
  background: var(--card-bg);
  color: var(--text-color);
  font-size: .9rem;
  font-family: inherit;
  transition: border-color .2s;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--link-color);
}

.field-hint {
  font-size: .75rem;
  color: var(--text-muted-color);
}

.contact-submit {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: .5rem;
  padding: .7rem 1.4rem;
  border: none;
  border-radius: 20px;
  background: var(--link-color);
  color: #fff;
  font-size: .9rem;
  font-weight: 600;
  cursor: pointer;
  transition: opacity .2s;
  align-self: flex-start;
}

.contact-submit:hover {
  opacity: .88;
}

.contact-status {
  font-size: .85rem;
  margin: 0;
  min-height: 1.2em;
}

.contact-status.sending { color: var(--text-muted-color); }
.contact-status.success { color: #2ecc71; font-weight: 600; }
.contact-status.error { color: #e74c3c; font-weight: 600; }

@media (max-width: 600px) {
  .contact-wrap { padding: 0 .5rem; }
}
</style>
