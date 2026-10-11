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
    // Load a same-origin stylesheet so strict style-src policies do not block the guide UI.
    const link = document.createElement('link');
    link.id = STYLE_ID;
    link.rel = 'stylesheet';
    link.href = 'assets/learn.css?v=1';
    document.head.appendChild(link);
  }

  // Update the positioning rule in the same-origin stylesheet instead of adding inline styles.
  function setCardPosition({ left, top, width }) {
    const sheetLink = document.getElementById(STYLE_ID);
    const sheet = sheetLink && sheetLink.sheet;
    if (!sheet) return;
    for (const rule of sheet.cssRules) {
      if (rule.selectorText === '#sp-learn-card') {
        rule.style.left = left + 'px';
        rule.style.top = top + 'px';
        rule.style.width = width + 'px';
        return;
      }
    }
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
    document.body.classList.add('sp-learn-open');
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
    const left = Math.max(14, Math.min(window.innerWidth - width - 14, rect.left + rect.width / 2 - width / 2));
    const cardHeight = card.offsetHeight;
    const below = window.innerHeight - rect.bottom - 18;
    const top = below >= Math.min(cardHeight, 220) ? rect.bottom + 14 : Math.max(14, rect.top - cardHeight - 14);
    setCardPosition({ left, top: Math.min(top, window.innerHeight - cardHeight - 14), width });
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
    document.body.classList.remove('sp-learn-open');
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
