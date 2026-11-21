// kvage site: menu toggle, scroll reveals, tagline word reveal, current section in the nav.
(function () {
  'use strict';

  var hasIO = 'IntersectionObserver' in window;

  // Mobile menu
  var toggle = document.querySelector('.nav-toggle');
  var menu = document.getElementById('menu');
  function setMenu(open) {
    menu.classList.toggle('open', open);
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    toggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    document.body.style.overflow = open ? 'hidden' : '';
  }
  if (toggle && menu) {
    toggle.addEventListener('click', function () {
      setMenu(toggle.getAttribute('aria-expanded') !== 'true');
    });
    menu.addEventListener('click', function (e) {
      if (e.target.closest('a')) setMenu(false);
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') {
        setMenu(false);
        toggle.focus();
      }
    });
    window.matchMedia('(min-width: 920px)').addEventListener('change', function (e) {
      if (e.matches) setMenu(false);
    });
  }

  // Scroll reveals, once per element
  var reveals = document.querySelectorAll('.reveal');
  if (hasIO) {
    var revealIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          revealIO.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -10% 0px' });
    reveals.forEach(function (el) { revealIO.observe(el); });
  } else {
    reveals.forEach(function (el) { el.classList.add('in'); });
  }

  // Tagline: split into words, light each one as it crosses the trigger line
  document.querySelectorAll('[data-words]').forEach(function (el) {
    var words = [];
    Array.prototype.slice.call(el.childNodes).forEach(function (node) {
      if (node.nodeType !== 3) return;
      var frag = document.createDocumentFragment();
      node.textContent.split(/(\s+)/).forEach(function (part) {
        if (!part) return;
        if (/^\s+$/.test(part)) { frag.appendChild(document.createTextNode(' ')); return; }
        var span = document.createElement('span');
        span.className = 'w';
        span.textContent = part;
        words.push(span);
        frag.appendChild(span);
      });
      el.replaceChild(frag, node);
    });
    if (!hasIO) { words.forEach(function (w) { w.classList.add('on'); }); return; }
    var wordIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (!entry.isIntersecting) return;
        var i = words.indexOf(entry.target);
        // Words on the same line cross together: step them in reading order.
        entry.target.style.transitionDelay = (i % 6) * 70 + 'ms';
        entry.target.classList.add('on');
        wordIO.unobserve(entry.target);
      });
    }, { rootMargin: '0px 0px -30% 0px' });
    words.forEach(function (w) { wordIO.observe(w); });
  });

  // Mark the section in view in the navigation
  if (hasIO && menu) {
    var links = {};
    menu.querySelectorAll('a[href^="#"]').forEach(function (a) {
      links[a.getAttribute('href').slice(1)] = a;
    });
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var link = links[entry.target.id];
        if (!link) return;
        if (entry.isIntersecting) {
          Object.keys(links).forEach(function (id) { links[id].removeAttribute('aria-current'); });
          link.setAttribute('aria-current', 'true');
        } else {
          link.removeAttribute('aria-current');
        }
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    Object.keys(links).forEach(function (id) {
      var section = document.getElementById(id);
      if (section) spy.observe(section);
    });
  }
})();
