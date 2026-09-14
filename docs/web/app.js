/**
 * Flareway Documentation Portal - Interactive Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initSidebar();
  initTabs();
  initCopyButtons();
  initSearch();
  initInteractiveDiagrams();
});

// Theme Management
function initTheme() {
  const themeBtn = document.getElementById('theme-toggle-btn');
  const storedTheme = localStorage.getItem('flareway-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', storedTheme);
  updateThemeIcon(storedTheme);

  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('flareway-theme', next);
      updateThemeIcon(next);
    });
  }
}

function updateThemeIcon(theme) {
  const icon = document.querySelector('#theme-toggle-btn i') || document.querySelector('#theme-toggle-btn span');
  if (icon) {
    icon.textContent = theme === 'dark' ? '☀️' : '🌙';
  }
}

// Sidebar Scrollspy & Navigation
function initSidebar() {
  const links = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('section.section');

  function onScroll() {
    let currentId = '';
    const scrollPos = window.scrollY + 120;

    sections.forEach(sec => {
      const top = sec.offsetTop;
      const height = sec.offsetHeight;
      if (scrollPos >= top && scrollPos < top + height) {
        currentId = sec.getAttribute('id');
      }
    });

    links.forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${currentId}`) {
        link.classList.add('active');
      }
    });
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}

// Tab Switching
function initTabs() {
  document.querySelectorAll('.tabs-container').forEach(container => {
    const btns = container.querySelectorAll('.tab-btn');
    const panes = container.querySelectorAll('.tab-content');

    btns.forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-tab');

        btns.forEach(b => b.classList.remove('active'));
        panes.forEach(p => p.classList.remove('active'));

        btn.classList.add('active');
        const activePane = container.querySelector(`.tab-content[data-tab="${target}"]`);
        if (activePane) activePane.classList.add('active');
      });
    });
  });
}

// Copy Code Snippets
function initCopyButtons() {
  document.querySelectorAll('.code-box').forEach(box => {
    const copyBtn = box.querySelector('.code-copy-btn');
    const pre = box.querySelector('pre');
    if (!copyBtn || !pre) return;

    copyBtn.addEventListener('click', async () => {
      try {
        const text = pre.innerText;
        await navigator.clipboard.writeText(text);
        const originalText = copyBtn.innerText;
        copyBtn.innerText = 'Copied!';
        copyBtn.style.borderColor = 'var(--color-success)';
        copyBtn.style.color = 'var(--color-success)';
        setTimeout(() => {
          copyBtn.innerText = originalText;
          copyBtn.style.borderColor = '';
          copyBtn.style.color = '';
        }, 2000);
      } catch (err) {
        console.error('Failed to copy', err);
      }
    });
  });
}

// Quick Search
function initSearch() {
  const searchInput = document.getElementById('global-search');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    const cards = document.querySelectorAll('.crd-card, .table-searchable tr');

    if (!query) {
      cards.forEach(c => c.style.display = '');
      return;
    }

    cards.forEach(card => {
      const text = card.textContent.toLowerCase();
      if (text.includes(query)) {
        card.style.display = '';
      } else {
        card.style.display = 'none';
      }
    });
  });
}

// Interactive Diagram Highlights
function initInteractiveDiagrams() {
  // Flow diagram switcher (Public vs Private)
  const flowTabs = document.querySelectorAll('.flow-switcher-btn');
  flowTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetFlow = btn.getAttribute('data-flow');
      flowTabs.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      document.querySelectorAll('.flow-diagram-view').forEach(view => {
        if (view.getAttribute('data-flow') === targetFlow) {
          view.style.display = 'block';
        } else {
          view.style.display = 'none';
        }
      });
    });
  });

  // Node tooltips / highlights on SVG
  const nodes = document.querySelectorAll('.svg-diagram .flow-node');
  const tooltip = document.getElementById('diagram-tooltip');

  nodes.forEach(node => {
    node.addEventListener('mouseenter', (e) => {
      const info = node.getAttribute('data-info');
      if (info && tooltip) {
        tooltip.innerHTML = info;
        tooltip.style.display = 'block';
      }
    });

    node.addEventListener('mousemove', (e) => {
      if (tooltip && tooltip.style.display === 'block') {
        tooltip.style.left = (e.pageX + 14) + 'px';
        tooltip.style.top = (e.pageY + 14) + 'px';
      }
    });

    node.addEventListener('mouseleave', () => {
      if (tooltip) tooltip.style.display = 'none';
    });
  });
}
