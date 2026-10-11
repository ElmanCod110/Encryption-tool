(() => {
  'use strict';

  // Keep the guide dependency-free so it works with the application's local-only asset policy.
  const STYLE_ID = 'sp-learn-styles';
  const BUTTON_ID = 'sp-learn-launcher';
  const OVERLAY_ID = 'sp-learn-overlay';
  const CARD_ID = 'sp-learn-card';
  const SPOTLIGHT_CLASS = 'sp-learn-spotlight';
  let activeIndex = -1;
  let steps = [];
  let previousFocus = null;
  let resizeFrame = 0;

  // Each page defines its own meaningful stops through data-learn attributes.
  // The total is calculated from the targets that are actually visible on that page.
  function collectSteps() {
    return [...document.querySelectorAll('[data-learn]')]
      .filter((target) => {
        if (!target.isConnected || target.hidden || target.closest('[hidden], .hidden, [aria-hidden="true"]')) return false;
        const style = window.getComputedStyle(target);
        return style.display !== 'none' && style.visibility !== 'hidden' && target.getClientRects().length > 0;
      })
      .map((target) => ({
        target,
        title: target.dataset.learnTitle || target.getAttribute('aria-label') || 'Explore this section',
        description: target.dataset.learn || 'This area is part of the application interface.',
      }));
  }

  // Create styles once instead of depending on a second stylesheet or a CSS framework.
  function installStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = `
      #${BUTTON_ID}{position:fixed;right:22px;bottom:22px;z-index:2147483000;width:48px;height:48px;border:1px solid #b7f36b;border-radius:50%;background:#b7f36b;color:#10170d;box-shadow:0 8px 28px rgba(0,0,0,.35);font:800 23px/1 system-ui,sans-serif;cursor:pointer;display:grid;place-items:center;transition:transform .18s ease,box-shadow .18s ease}
      #${BUTTON_ID}:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(0,0,0,.42)}
      #${BUTTON_ID}:focus-visible,#${CARD_ID} button:focus-visible{outline:3px solid #fff;outline-offset:3px}
      #${OVERLAY_ID}{position:fixed;inset:0;z-index:2147482000;background:rgba(2,7,10,.62);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px)}
      .${SPOTLIGHT_CLASS}{position:relative!important;z-index:2147482500!important;isolation:isolate!important;outline:2px solid #b7f36b!important;outline-offset:5px!important;box-shadow:0 0 0 9999px rgba(2,7,10,.78),0 0 0 7px rgba(183,243,107,.22)!important;border-radius:7px!important;filter:none!important}
      #${CARD_ID}{position:fixed;z-index:2147483001;width:min(440px,calc(100vw - 28px));max-height:min(330px,calc(100vh - 28px));overflow:auto;padding:20px;border:1px solid #526b4b;border-radius:10px;background:#111b23;color:#edf4f5;box-shadow:0 24px 80px rgba(0,0,0,.5);font:14px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
      #${CARD_ID} .sp-learn-top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px;color:#b7f36b;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
      #${CARD_ID} .sp-learn-close{width:30px;height:30px;border:1px solid #354954;border-radius:6px;background:#17232c;color:#dbe6e8;font-size:19px;cursor:pointer}
      #${CARD_ID} h2{margin:0 0 9px;color:#f1f6f6;font-size:20px;line-height:1.25;letter-spacing:-.035em}
      #${CARD_ID} p{margin:0;color:#b4c4c9;font-size:13px;line-height:1.8;white-space:pre-line}
      #${CARD_ID} .sp-learn-footer{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:19px;padding-top:14px;border-top:1px solid #2a3b45}
      #${CARD_ID} .sp-learn-count{color:#92a7af;font-size:11px;font-variant-numeric:tabular-nums}
      #${CARD_ID} .sp-learn-actions{display:flex;gap:7px}
      #${CARD_ID} .sp-learn-actions button{min-height:35px;padding:8px 12px;border:1px solid #3c505b;border-radius:6px;background:#17232c;color:#dce6e8;font-size:12px;font-weight:750;cursor:pointer}
      #${CARD_ID} .sp-learn-actions button[data-action="next"],#${CARD_ID} .sp-learn-actions button[data-action="finish"]{border-color:#b7f36b;background:#b7f36b;color:#10170d}
      #${CARD_ID} .sp-learn-actions button:disabled{opacity:.4;cursor:not-allowed}
      @media(max-width:520px){#${BUTTON_ID}{right:15px;bottom:15px;width:44px;height:44px}#${CARD_ID}{padding:16px}#${CARD_ID} h2{font-size:18px}}
      @media(prefers-reduced-motion:reduce){#${BUTTON_ID}{transition:none}}
    `;
    document.head.appendChild(style);
  }

  // Use DOM nodes and textContent for all copy so tutorial text is never interpreted as markup.
  function buildInterface() {
    let launcher = document.getElementById(BUTTON_ID);
    if (!launcher) {
      launcher = document.createElement('button');
      launcher.id = BUTTON_ID;
      launcher.type = 'button';
      launcher.textContent = '?';
      launcher.setAttribute('aria-label', 'Open the guided interface tour');
      launcher.title = 'Guided tour';
      launcher.addEventListener('click', start);
      document.body.appendChild(launcher);
    }

    let overlay = document.getElementById(OVERLAY_ID);
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = OVERLAY_ID;
      overlay.hidden = true;
      overlay.setAttribute('aria-hidden', 'true');
      overlay.addEventListener('click', (event) => {
        if (event.target === overlay) finish();
      });
      document.body.appendChild(overlay);
    }

    let card = document.getElementById(CARD_ID);
    if (!card) {
      card = document.createElement('section');
      card.id = CARD_ID;
      card.hidden = true;
      card.setAttribute('role', 'dialog');
      card.setAttribute('aria-modal', 'true');
      card.setAttribute('aria-labelledby', 'sp-learn-title');
      card.innerHTML = '<div class="sp-learn-top"><span>Guided tour</span><button class="sp-learn-close" type="button" data-action="close" aria-label="Close guide">×</button></div><h2 id="sp-learn-title"></h2><p id="sp-learn-description"></p><div class="sp-learn-footer"><span class="sp-learn-count" id="sp-learn-count"></span><div class="sp-learn-actions"><button type="button" data-action="previous">Back</button><button type="button" data-action="next">Next</button><button type="button" data-action="finish" hidden>Finish</button></div></div>';
      card.addEventListener('click', (event) => {
        const button = event.target.closest('button[data-action]');
        if (!button) return;
        const action = button.dataset.action;
        if (action === 'close' || action === 'finish') finish();
        if (action === 'previous') showStep(activeIndex - 1);
        if (action === 'next') showStep(activeIndex + 1);
      });
      document.body.appendChild(card);
    }
  }

  // A tour always starts from a fresh count, including elements revealed after an upload.
  function start() {
    steps = collectSteps();
    if (!steps.length) {
      window.alert('There are no visible guide steps on this screen yet.');
      return;
    }
    previousFocus = document.activeElement;
    document.getElementById(OVERLAY_ID).hidden = false;
    document.getElementById(CARD_ID).hidden = false;
    document.getElementById(BUTTON_ID).setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
    showStep(0);
  }

  // Move focus to the selected target and keep the explanation near it whenever possible.
  function showStep(index) {
    if (index < 0 || index >= steps.length) return;
    activeIndex = index;
    const step = steps[activeIndex];
    if (!step.target.isConnected || !step.target.getClientRects().length) {
      steps = collectSteps();
      activeIndex = Math.min(activeIndex, steps.length - 1);
      if (!steps.length) return finish();
      return showStep(activeIndex);
    }

    steps.forEach(({ target }) => target.classList.remove(SPOTLIGHT_CLASS));
    step.target.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center', inline: 'nearest' });
    step.target.classList.add(SPOTLIGHT_CLASS);

    document.getElementById('sp-learn-title').textContent = step.title;
    document.getElementById('sp-learn-description').textContent = step.description;
    document.getElementById('sp-learn-count').textContent = `${activeIndex + 1} / ${steps.length}`;
    document.querySelector('#' + CARD_ID + ' [data-action="previous"]').disabled = activeIndex === 0;
    document.querySelector('#' + CARD_ID + ' [data-action="next"]').hidden = activeIndex === steps.length - 1;
    document.querySelector('#' + CARD_ID + ' [data-action="finish"]').hidden = activeIndex !== steps.length - 1;

    // Wait a frame for scrolling/layout, then position the modal below the spotlight if space allows.
    requestAnimationFrame(positionCard);
    document.querySelector('#' + CARD_ID + ' [data-action="close"]').focus({ preventScroll: true });
  }

  // Positioning is recalculated after viewport changes to keep the explanation on-screen.
  function positionCard() {
    const card = document.getElementById(CARD_ID);
    const target = steps[activeIndex]?.target;
    if (!card || card.hidden || !target) return;
    const rect = target.getBoundingClientRect();
    const width = Math.min(440, window.innerWidth - 28);
    card.style.width = width + 'px';
    card.style.left = Math.max(14, Math.min(window.innerWidth - width - 14, rect.left + rect.width / 2 - width / 2)) + 'px';
    const cardHeight = card.offsetHeight;
    const below = window.innerHeight - rect.bottom - 18;
    const top = below >= Math.min(cardHeight, 220) ? rect.bottom + 14 : Math.max(14, rect.top - cardHeight - 14);
    card.style.top = Math.min(top, window.innerHeight - cardHeight - 14) + 'px';
  }

  // Remove the spotlight and restore scrolling/focus without changing the underlying application state.
  function finish() {
    document.querySelectorAll('.' + SPOTLIGHT_CLASS).forEach((target) => target.classList.remove(SPOTLIGHT_CLASS));
    const overlay = document.getElementById(OVERLAY_ID);
    const card = document.getElementById(CARD_ID);
    if (overlay) overlay.hidden = true;
    if (card) card.hidden = true;
    const launcher = document.getElementById(BUTTON_ID);
    if (launcher) launcher.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
    activeIndex = -1;
    steps = [];
    if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus({ preventScroll: true });
  }

  // Keyboard controls make the guide usable without a mouse.
  document.addEventListener('keydown', (event) => {
    if (activeIndex < 0) return;
    if (event.key === 'Escape') { event.preventDefault(); finish(); }
    else if (event.key === 'ArrowRight') { event.preventDefault(); showStep(activeIndex + 1); }
    else if (event.key === 'ArrowLeft') { event.preventDefault(); showStep(activeIndex - 1); }
    else if (event.key === 'Tab') {
      const buttons = [...document.querySelectorAll('#' + CARD_ID + ' button:not([hidden]):not(:disabled)')];
      if (!buttons.length) return;
      const first = buttons[0], last = buttons[buttons.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });

  // Resize and orientation changes should never leave the modal outside the viewport.
  window.addEventListener('resize', () => {
    if (activeIndex < 0) return;
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(positionCard);
  });
  window.addEventListener('orientationchange', () => {
    if (activeIndex >= 0) requestAnimationFrame(positionCard);
  });

  // Install after the DOM is ready so the shared helper also works with deferred scripts.
  function init() {
    installStyles();
    buildInterface();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();

  // Expose a tiny public API for pages that reveal new UI and want to restart the count.
  window.SecurePackageLearn = Object.freeze({
    start,
    refresh: () => { steps = collectSteps(); return steps.length; },
    finish,
    count: () => collectSteps().length,
  });
})();
