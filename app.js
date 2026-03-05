/**
 * Family Tree – D3.js Interactive Viewer
 * Secure: Data encrypted with AES-256-GCM, decrypted client-side after login
 */
(function () {
  'use strict';

  const $ = s => document.querySelector(s);

  // ============================================
  // Authentication System
  // ============================================
  async function sha256(message) {
    const enc = new TextEncoder().encode(message);
    const hash = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function b64ToArrayBuffer(base64) {
    const bin = atob(base64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }

  async function deriveKey(password, salt, iterations) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptData(password) {
    const salt = b64ToArrayBuffer(AUTH_DATA.salt);
    const nonce = b64ToArrayBuffer(AUTH_DATA.nonce);
    const ciphertext = b64ToArrayBuffer(AUTH_DATA.ciphertext);
    const key = await deriveKey(password, salt, AUTH_DATA.iterations);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      ciphertext
    );
    const json = new TextDecoder().decode(decrypted);
    return JSON.parse(json);
  }

  async function handleLogin(e) {
    e.preventDefault();
    const user = $('#login-user').value.trim();
    const pass = $('#login-pass').value;
    const errorEl = $('#login-error');
    const btnText = $('#login-btn-text');
    const spinner = $('#login-spinner');
    const btn = $('#login-btn');

    errorEl.classList.add('hidden');
    btn.disabled = true;
    btnText.textContent = 'جاري التحقق...';
    spinner.classList.remove('hidden');

    try {
      // Verify credentials hash
      const credHash = await sha256(user + ':' + pass);
      if (credHash !== AUTH_DATA.credHash) {
        throw new Error('invalid');
      }

      // Decrypt data
      const familyData = await decryptData(pass);

      // Store session
      sessionStorage.setItem('ft_auth', '1');
      sessionStorage.setItem('ft_session_time', Date.now().toString());

      // Hide login, show app
      $('#login-screen').classList.add('hidden');
      $('#loading-screen').classList.remove('hidden');

      // Initialize the tree
      initializeTree(familyData);

    } catch (err) {
      errorEl.classList.remove('hidden');
      btn.disabled = false;
      btnText.textContent = 'تسجيل الدخول';
      spinner.classList.add('hidden');
      // Shake animation
      errorEl.style.animation = 'none';
      requestAnimationFrame(() => { errorEl.style.animation = ''; });
    }
  }

  // Password visibility toggle
  $('#pass-toggle').addEventListener('click', () => {
    const input = $('#login-pass');
    input.type = input.type === 'password' ? 'text' : 'password';
  });

  // Login form submit
  $('#login-form').addEventListener('submit', handleLogin);

  // Allow Enter key
  $('#login-pass').addEventListener('keydown', e => {
    if (e.key === 'Enter') handleLogin(e);
  });

  // Logout
  $('#btn-logout').addEventListener('click', () => {
    sessionStorage.removeItem('ft_auth');
    sessionStorage.removeItem('ft_session_time');
    location.reload();
  });

  // Session timeout (4 hours)
  const SESSION_TIMEOUT = 4 * 60 * 60 * 1000;
  function checkSession() {
    const t = sessionStorage.getItem('ft_session_time');
    if (t && Date.now() - parseInt(t) > SESSION_TIMEOUT) {
      sessionStorage.removeItem('ft_auth');
      sessionStorage.removeItem('ft_session_time');
      location.reload();
    }
  }
  setInterval(checkSession, 60000);

  // Prevent right-click context menu on sensitive areas
  document.addEventListener('contextmenu', e => {
    if (e.target.closest('#tree-viewport') || e.target.closest('.modal')) {
      e.preventDefault();
    }
  });

  // ============================================
  // Main App (called after successful auth)
  // ============================================
  function initializeTree(familyData) {

  // ============================================
  // SVG Icons (replacing emojis)
  // ============================================
  const IC = {
    pin: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>',
    male: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="7" r="4"/><path d="M5.5 21a6.5 6.5 0 0 1 13 0"/></svg>',
    female: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="7" r="4"/><path d="M5.5 21a6.5 6.5 0 0 1 13 0"/></svg>',
    dove: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2z"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>',
    ring: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78L12 21.23l8.84-8.84a5.5 5.5 0 0 0 0-7.78z"/></svg>',
    child: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="4" r="2.5"/><path d="M12 6.5v4"/><circle cx="7" cy="17" r="2"/><circle cx="17" cy="17" r="2"/><line x1="12" y1="10.5" x2="7" y2="15"/><line x1="12" y1="10.5" x2="17" y2="15"/></svg>',
    peace: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
  };

  function genderIcon(gender) { return gender === 'female' ? IC.female : IC.male; }

  // ============================================
  // Helpers
  // ============================================
  // Deceased ancestor IDs (ثابت and above)
  const deceasedIds = new Set(['1','2','3','4','5','6','7']);

  // Generation names — ثابت (depth 6 in tree) is الجيل الأول
  const THABIT_DEPTH = 6;
  function getGenName(depth) {
    const genIdx = depth - THABIT_DEPTH;
    const names = ['الجيل الأول','الجيل الثاني','الجيل الثالث','الجيل الرابع','الجيل الخامس'];
    if (genIdx >= 0 && genIdx < names.length) return names[genIdx];
    if (genIdx < 0) return 'الأجداد';
    return 'الجيل ' + (genIdx + 1);
  }

  function getInitials(name) {
    const parts = name.split(' ');
    return parts.length > 1 ? parts[0][0] + parts[1][0] : parts[0].substring(0, 2);
  }

  function flattenTree(node, depth, parent) {
    depth = depth || 0; parent = parent || null;
    const list = [{ ...node, depth, parentId: parent ? parent.id : null }];
    if (node.children) node.children.forEach(c => list.push(...flattenTree(c, depth + 1, node)));
    return list;
  }

  function findInTree(node, id) {
    if (node.id === id) return node;
    if (node.children) for (const c of node.children) { const r = findInTree(c, id); if (r) return r; }
    return null;
  }

  function findParent(node, id, par) {
    if (node.id === id) return par;
    if (node.children) for (const c of node.children) { const r = findParent(c, id, node); if (r) return r; }
    return null;
  }

  function getAncestors(root, id) {
    const path = [];
    function walk(n) {
      path.push(n);
      if (n.id === id) return true;
      if (n.children) for (const c of n.children) { if (walk(c)) return true; }
      path.pop();
      return false;
    }
    walk(root);
    return path;
  }

  const allPersons = flattenTree(familyData);
  let currentModalIdx = -1;

  // ============================================
  // DOM
  // ============================================
  const svg = d3.select('#tree-svg');
  const container = svg.append('g').attr('class', 'tree-container');
  const linkGroup = container.append('g').attr('class', 'links-group');
  const nodeGroup = container.append('g').attr('class', 'nodes-group');

  // ============================================
  // State
  // ============================================
  const collapsed = new Set();
  let darkMode = localStorage.getItem('ft_dark') === '1';

  // ============================================
  // D3 Zoom
  // ============================================
  const zoomBehavior = d3.zoom()
    .scaleExtent([0.1, 3])
    .on('zoom', (e) => {
      container.attr('transform', e.transform);
      $('#zoom-label').textContent = Math.round(e.transform.k * 100) + '%';
    });

  svg.call(zoomBehavior)
    .on('dblclick.zoom', null); // disable double-click zoom

  // Track drag state for cursor styling
  svg.on('mousedown.grab', () => $('#tree-viewport').classList.add('grabbing'))
     .on('mouseup.grab', () => $('#tree-viewport').classList.remove('grabbing'));

  // ============================================
  // Build and Render Tree
  // ============================================
  const NODE_W = 170;
  const NODE_H = 110;
  const NODE_PAD_X = 30;
  const NODE_PAD_Y = 50;
  const SPOUSE_W = 115;
  const SPOUSE_H = 74;
  const SPOUSE_GAP = 14;

  function getVisibleHierarchy() {
    function prune(node) {
      const copy = { ...node, _data: node };
      if (collapsed.has(node.id) || !node.children || node.children.length === 0) {
        copy.children = null;
        copy._childCount = node.children ? node.children.length : 0;
      } else {
        copy.children = node.children.map(prune);
        copy._childCount = 0;
      }
      return copy;
    }
    return d3.hierarchy(prune(familyData));
  }

  function renderTree(animate) {
    const root = getVisibleHierarchy();

    const treeLayout = d3.tree()
      .nodeSize([NODE_W + NODE_PAD_X, NODE_H + NODE_PAD_Y])
      .separation((a, b) => {
        const aS = a.data._data.spouse ? 1 : 0;
        const bS = b.data._data.spouse ? 1 : 0;
        const base = a.parent === b.parent ? 1 : 1.15;
        return base + Math.max(aS, bS) * 0.6;
      });

    treeLayout(root);

    // ---- LINKS ----
    const linkData = root.links();
    const links = linkGroup.selectAll('.tree-link').data(linkData, d => d.target.data.id);

    links.exit().transition().duration(animate ? 300 : 0).style('opacity', 0).remove();

    const linkEnter = links.enter().append('path').attr('class', 'tree-link')
      .style('opacity', 0);

    const linkMerge = linkEnter.merge(links);
    linkMerge.transition().duration(animate ? 500 : 0)
      .style('opacity', d => {
        const inSpot = spotlightIds.has(d.source.data.id) && spotlightIds.has(d.target.data.id);
        return inSpot ? 1 : 0.08;
      })
      .attr('d', d => {
        const sx = d.source.x;
        const sy = d.source.y + NODE_H / 2 + 4;
        const tx = d.target.x;
        const ty = d.target.y - NODE_H / 2;
        const my = sy + (ty - sy) / 2;
        return `M${sx},${sy} L${sx},${my} L${tx},${my} L${tx},${ty}`;
      });


    // ---- NODES ----
    const nodeData = root.descendants();
    const nodes = nodeGroup.selectAll('.node-group').data(nodeData, d => d.data.id);

    nodes.exit().transition().duration(animate ? 300 : 0).style('opacity', 0).remove();

    const nodeEnter = nodes.enter().append('g')
      .attr('class', d => {
        let cls = 'node-group';
        if (d.data._data.gender === 'female') cls += ' female';
        if (d.data._data.children && d.data._data.children.length > 0) cls += ' has-children';
        if (d.data._data.deceased) cls += ' deceased';
        return cls;
      })
      .attr('transform', d => `translate(${d.x},${d.y})`)
      .style('opacity', 0);

    // Node rectangle
    nodeEnter.append('rect').attr('class', 'node-rect')
      .attr('x', -NODE_W / 2).attr('y', -NODE_H / 2)
      .attr('width', NODE_W).attr('height', NODE_H);

    // Avatar circle
    nodeEnter.append('circle').attr('class', 'node-circle')
      .attr('cx', 0).attr('cy', -NODE_H / 2 + 28).attr('r', 18);

    // Person icon (male/female silhouette)
    nodeEnter.each(function(d) {
      const g = d3.select(this);
      const cy = -NODE_H / 2 + 28;
      if (d.data._data.gender === 'female') {
        // Female icon
        g.append('circle').attr('class', 'icon-head').attr('cx', 0).attr('cy', cy - 6).attr('r', 5);
        g.append('path').attr('class', 'icon-body')
          .attr('d', `M-7,${cy + 8} Q-7,${cy + 1} 0,${cy + 1} Q7,${cy + 1} 7,${cy + 8} L4,${cy + 8} L2,${cy + 14} L-2,${cy + 14} L-4,${cy + 8} Z`);
      } else {
        // Male icon
        g.append('circle').attr('class', 'icon-head').attr('cx', 0).attr('cy', cy - 6).attr('r', 5);
        g.append('path').attr('class', 'icon-body')
          .attr('d', `M-6,${cy + 8} Q-6,${cy + 1} 0,${cy + 1} Q6,${cy + 1} 6,${cy + 8} L6,${cy + 14} L-6,${cy + 14} Z`);
      }
    });

    // Name
    nodeEnter.append('text').attr('class', 'person-name')
      .attr('x', 0).attr('y', -NODE_H / 2 + 66)
      .attr('text-anchor', 'middle')
      .text(d => d.data._data.name);

    // Title
    nodeEnter.append('text').attr('class', 'person-title')
      .attr('x', 0).attr('y', -NODE_H / 2 + 82)
      .attr('text-anchor', 'middle')
      .text(d => d.data._data.title || '');

    // Toggle button for collapsed nodes with children
    const toggleG = nodeEnter.filter(d => d.data._data.children && d.data._data.children.length > 0)
      .append('g').attr('class', 'toggle-group')
      .attr('transform', `translate(0, ${NODE_H / 2 - 4})`);

    toggleG.append('circle').attr('class', 'toggle-bg')
      .attr('r', 11);

    toggleG.append('text').attr('class', 'toggle-text')
      .attr('text-anchor', 'middle').attr('y', 4)
      .text(d => collapsed.has(d.data.id)
        ? d.data._data.children.length
        : '▲');

    // ---- SPOUSE NODES ----
    nodeEnter.filter(d => d.data._data.spouse).each(function(d) {
      const g = d3.select(this);
      const spouseX = NODE_W / 2 + SPOUSE_GAP + SPOUSE_W / 2;
      const isMaleSpouse = d.data._data.gender === 'female';

      // Horizontal dashed connector
      g.append('line').attr('class', 'spouse-link')
        .attr('x1', NODE_W / 2).attr('y1', 0)
        .attr('x2', NODE_W / 2 + SPOUSE_GAP).attr('y2', 0);

      // Spouse group
      const sg = g.append('g').attr('class', 'spouse-group')
        .attr('transform', `translate(${spouseX}, 0)`);

      sg.append('rect').attr('class', 'spouse-rect')
        .attr('x', -SPOUSE_W / 2).attr('y', -SPOUSE_H / 2)
        .attr('width', SPOUSE_W).attr('height', SPOUSE_H)
        .attr('rx', 16).attr('ry', 16);

      // Spouse avatar circle
      const acy = -SPOUSE_H / 2 + 22;
      sg.append('circle').attr('class', 'spouse-avatar')
        .attr('cx', 0).attr('cy', acy).attr('r', 14);

      // Icon
      sg.append('circle').attr('class', 'spouse-icon')
        .attr('cx', 0).attr('cy', acy - 5).attr('r', 4);
      if (isMaleSpouse) {
        sg.append('path').attr('class', 'spouse-icon')
          .attr('d', `M-5,${acy + 6} Q-5,${acy} 0,${acy} Q5,${acy} 5,${acy + 6} L5,${acy + 11} L-5,${acy + 11} Z`);
      } else {
        sg.append('path').attr('class', 'spouse-icon')
          .attr('d', `M-6,${acy + 6} Q-6,${acy} 0,${acy} Q6,${acy} 6,${acy + 6} L3,${acy + 6} L1,${acy + 11} L-1,${acy + 11} L-3,${acy + 6} Z`);
      }

      // Spouse name
      sg.append('text').attr('class', 'spouse-name')
        .attr('x', 0).attr('y', -SPOUSE_H / 2 + 50)
        .attr('text-anchor', 'middle')
        .text(d.data._data.spouse);

      // Label
      sg.append('text').attr('class', 'spouse-label')
        .attr('x', 0).attr('y', -SPOUSE_H / 2 + 64)
        .attr('text-anchor', 'middle')
        .text(isMaleSpouse ? '\u0627\u0644\u0632\u0648\u062c' : '\u0627\u0644\u0632\u0648\u062c\u0629');
    });

    // Events
    nodeEnter.on('click', function (event, d) {
      event.stopPropagation();
      hideTooltip();
      openModal(d.data._data, d.depth);
    });

    nodeEnter.on('mouseenter', function (event, d) {
      highlightAncestors(d.data.id, true);
      showTooltip(event, d.data._data, d.depth);
    }).on('mousemove', function (event) {
      moveTooltip(event);
    }).on('mouseleave', function () {
      highlightAncestors(null);
      hideTooltip();
    });

    // Toggle click
    toggleG.on('click', function (event, d) {
      event.stopPropagation();
      toggleCollapse(d.data.id);
    });

    // Merge + transition
    const nodeMerge = nodeEnter.merge(nodes);
    nodeMerge.transition().duration(animate ? 500 : 0)
      .attr('transform', d => `translate(${d.x},${d.y})`)
      .style('opacity', d => spotlightIds.has(d.data.id) ? (d.data._data.deceased ? 0.55 : 1) : 0.18);

    // Update toggle text
    nodeMerge.select('.toggle-text')
      .text(d => {
        if (!d.data._data.children || d.data._data.children.length === 0) return '';
        return collapsed.has(d.data.id) ? d.data._data.children.length : '▲';
      });

    // Update classes
    nodeMerge.attr('class', d => {
      let cls = 'node-group';
      if (d.data._data.gender === 'female') cls += ' female';
      if (d.data._data.children && d.data._data.children.length > 0) cls += ' has-children';
      if (d.data._data.deceased) cls += ' deceased';
      return cls;
    });

    // Re-apply spotlight after any render
    requestAnimationFrame(() => applySpotlight());
  }

  function toggleCollapse(id) {
    if (collapsed.has(id)) {
      collapsed.delete(id);
      toast('تم توسيع الفرع');
    } else {
      collapsed.add(id);
      toast('تم طي الفرع');
    }
    renderTree(true);
  }

  // ============================================
  // Highlight ancestors
  // ============================================
  function highlightAncestors(id, show) {
    linkGroup.selectAll('.tree-link').classed('highlighted', false);
    nodeGroup.selectAll('.node-group').classed('highlight', false);
    if (!id || !show) return;

    const chain = getAncestors(familyData, id);
    const ids = new Set(chain.map(n => n.id));

    linkGroup.selectAll('.tree-link').classed('highlighted', d => {
      return ids.has(d.source.data.id) && ids.has(d.target.data.id);
    });

    nodeGroup.selectAll('.node-group').classed('highlight', d => ids.has(d.data.id));
  }

  // ============================================
  // Tooltip
  // ============================================
  const tooltipEl = $('#tooltip');
  let ttTimeout;

  function showTooltip(event, person, depth) {
    clearTimeout(ttTimeout);
    ttTimeout = setTimeout(() => {
      const genName = getGenName(depth);
      let html = `<div class="tt-name">${person.name}</div>`;
      html += `<div class="tt-title">${person.title || ''}</div>`;
      html += `<div class="tt-info">`;
      html += `<span>${IC.pin} ${genName}</span>`;
      html += `<span>${genderIcon(person.gender)} ${person.gender === 'female' ? 'أنثى' : 'ذكر'}</span>`;
      if (person.deceased) html += `<span>${IC.peace} متوفى</span>`;
      if (person.spouse) html += `<span>${IC.ring} ${person.spouse}</span>`;
      if (person.children && person.children.length > 0) html += `<span>${IC.child} ${person.children.length} ${person.children.length > 2 ? 'أبناء' : person.children.length === 2 ? 'ابنان' : 'ابن'}</span>`;
      html += `</div>`;
      tooltipEl.innerHTML = html;
      tooltipEl.classList.remove('hidden');
      moveTooltip(event);
    }, 250);
  }

  function moveTooltip(event) {
    const pad = 14;
    let x = event.clientX + pad;
    let y = event.clientY + pad;
    const w = tooltipEl.offsetWidth;
    const h = tooltipEl.offsetHeight;
    if (x + w > window.innerWidth - 10) x = event.clientX - w - pad;
    if (y + h > window.innerHeight - 10) y = event.clientY - h - pad;
    tooltipEl.style.left = x + 'px';
    tooltipEl.style.top = y + 'px';
  }

  function hideTooltip() {
    clearTimeout(ttTimeout);
    tooltipEl.classList.add('hidden');
  }

  // ============================================
  // Modal
  // ============================================
  function openModal(person, depth) {
    currentModalIdx = allPersons.findIndex(p => p.id === person.id);
    const parent = findParent(familyData, person.id, null);
    const genName = getGenName(depth);
    const isFemale = person.gender === 'female';

    let h = `<div class="mp-avatar${isFemale ? ' female' : ''}">${genderIcon(person.gender)}</div>`;
    h += `<div class="mp-name">${person.name}</div>`;
    h += `<div class="mp-title">${person.title || ''}</div>`;
    h += `<div class="mp-fields">`;
    h += `<div class="mp-field"><span class="label">الجيل</span><span class="value">${genName}</span></div>`;
    h += `<div class="mp-field"><span class="label">الجنس</span><span class="value">${isFemale ? 'أنثى' : 'ذكر'}</span></div>`;
    if (person.deceased) h += `<div class="mp-field"><span class="label">الحالة</span><span class="value">${IC.peace} متوفى</span></div>`;
    if (person.spouse) h += `<div class="mp-field"><span class="label">الزوج/ة</span><span class="value">${person.spouse}</span></div>`;
    if (parent) h += `<div class="mp-field"><span class="label">الأب/الأم</span><span class="value">${parent.name}</span></div>`;
    if (person.profession) h += `<div class="mp-field"><span class="label">المهنة</span><span class="value">${person.profession}</span></div>`;
    h += `</div>`;
    if (person.bio) h += `<div class="mp-bio">${person.bio}</div>`;
    if (person.children && person.children.length > 0) {
      h += `<div class="mp-children"><h4>الأبناء (${person.children.length})</h4><div class="mp-child-list">`;
      person.children.forEach(c => {
        h += `<span class="mp-child-tag" data-id="${c.id}">${c.name}</span>`;
      });
      h += `</div></div>`;
    }

    $('#modal-body').innerHTML = h;
    $('#modal-overlay').classList.remove('hidden');

    // child tag clicks
    $('#modal-body').querySelectorAll('.mp-child-tag').forEach(el => {
      el.addEventListener('click', () => {
        const child = findInTree(familyData, el.dataset.id);
        if (child) {
          const cd = allPersons.find(p => p.id === child.id);
          openModal(child, cd ? cd.depth : depth + 1);
        }
      });
    });
  }

  function closeModal() { $('#modal-overlay').classList.add('hidden'); }

  function navModal(dir) {
    if (currentModalIdx < 0) return;
    currentModalIdx = (currentModalIdx + dir + allPersons.length) % allPersons.length;
    const p = allPersons[currentModalIdx];
    const node = findInTree(familyData, p.id);
    openModal(node || p, p.depth);
  }

  $('#modal-close').addEventListener('click', closeModal);
  $('#modal-prev').addEventListener('click', () => navModal(-1));
  $('#modal-next').addEventListener('click', () => navModal(1));
  $('#modal-overlay').addEventListener('click', e => { if (e.target === e.currentTarget) closeModal(); });


  // ============================================
  // Search
  // ============================================
  const searchInput = $('#search-input');
  const searchResults = $('#search-results');
  let searchDebounce;

  searchInput.addEventListener('input', () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(doSearch, 200);
  });

  function doSearch() {
    const q = searchInput.value.trim();
    if (!q) { searchResults.classList.add('hidden'); return; }
    const matches = allPersons.filter(p => p.name.includes(q) || (p.title && p.title.includes(q)));
    if (matches.length === 0) {
      searchResults.innerHTML = '<div class="sr-empty">لا توجد نتائج</div>';
    } else {
      searchResults.innerHTML = matches.slice(0, 10).map(p => {
        const fem = p.gender === 'female';
        return `<div class="sr-item" data-id="${p.id}">
          <div class="sr-icon${fem ? ' female' : ''}">${genderIcon(p.gender)}</div>
          <div><div class="sr-name">${p.name}</div><div class="sr-title">${p.title || ''}</div></div>
        </div>`;
      }).join('');
    }
    searchResults.classList.remove('hidden');
    searchResults.querySelectorAll('.sr-item').forEach(el => {
      el.addEventListener('click', () => {
        const person = findInTree(familyData, el.dataset.id);
        const pd = allPersons.find(p => p.id === el.dataset.id);
        if (person) {
          searchResults.classList.add('hidden');
          searchInput.value = '';
          if (mobileSearchInput) mobileSearchInput.value = '';
          if (mobileSearchBar) mobileSearchBar.classList.add('hidden');
          // Expand ancestors
          expandToNode(el.dataset.id);
          renderTree(true);
          // Zoom to node after render
          requestAnimationFrame(() => {
            requestAnimationFrame(() => {
              zoomToNode(el.dataset.id);
              openModal(person, pd ? pd.depth : 0);
            });
          });
        }
      });
    });
  }

  function expandToNode(id) {
    const chain = getAncestors(familyData, id);
    chain.forEach(n => collapsed.delete(n.id));
  }

  const isMobile = () => window.innerWidth <= 480;

  function zoomToNode(id) {
    const found = nodeGroup.selectAll('.node-group').filter(d => d.data.id === id);
    if (found.empty()) return;
    const d = found.datum();
    const vp = $('#tree-viewport');
    const w = vp.clientWidth;
    const h = vp.clientHeight;
    const mobile = isMobile();
    // Use smaller scale if node has many children or on mobile
    const hasMany = d.data._data.children && d.data._data.children.length > 4;
    const scale = mobile ? (hasMany ? 0.45 : 0.8) : (hasMany ? 0.6 : 1.2);
    const ty_offset = hasMany ? (mobile ? -40 : -80) : 0;
    const tx = w / 2 - d.x * scale;
    const ty = h / 2 - d.y * scale + ty_offset;
    svg.transition().duration(600)
      .call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));

    // Flash highlight
    found.classed('highlight', true);
    setTimeout(() => found.classed('highlight', false), 2000);
  }

  // Close search on click outside
  document.addEventListener('click', e => {
    if (!$('#search-box').contains(e.target) && !searchResults.contains(e.target)) {
      searchResults.classList.add('hidden');
    }
  });

  // ============================================
  // Mobile Search
  // ============================================
  const mobileSearchBar = $('#mobile-search-bar');
  const mobileSearchInput = $('#mobile-search-input');
  const mobileSearchBtn = $('#btn-mobile-search');
  const mobileSearchClose = $('#mobile-search-close');

  if (mobileSearchBtn) {
    mobileSearchBtn.addEventListener('click', () => {
      mobileSearchBar.classList.remove('hidden');
      mobileSearchInput.focus();
    });
  }
  if (mobileSearchClose) {
    mobileSearchClose.addEventListener('click', () => {
      mobileSearchBar.classList.add('hidden');
      mobileSearchInput.value = '';
      searchResults.classList.add('hidden');
    });
  }
  if (mobileSearchInput) {
    let mobileDebounce;
    mobileSearchInput.addEventListener('input', () => {
      clearTimeout(mobileDebounce);
      mobileDebounce = setTimeout(() => {
        // Sync to main search
        searchInput.value = mobileSearchInput.value;
        doSearch();
      }, 200);
    });
  }

  // ============================================
  // Dark Mode
  // ============================================
  function applyDarkMode() {
    document.documentElement.setAttribute('data-theme', darkMode ? 'dark' : '');
    $('#dark-label').textContent = darkMode ? 'نهاري' : 'ليلي';
    const metaTheme = $('#meta-theme');
    if (metaTheme) metaTheme.content = darkMode ? '#0e0e0e' : '#f8f9fa';
    localStorage.setItem('ft_dark', darkMode ? '1' : '0');
    // Force re-render for style updates
    renderTree(false);
  }

  $('#btn-dark').addEventListener('click', () => { darkMode = !darkMode; applyDarkMode(); });

  // ============================================
  // Controls
  // ============================================
  $('#btn-zin').addEventListener('click', () => svg.transition().duration(250).call(zoomBehavior.scaleBy, 1.25));
  $('#btn-zout').addEventListener('click', () => svg.transition().duration(250).call(zoomBehavior.scaleBy, 0.8));

  $('#btn-fit').addEventListener('click', fitView);
  $('#btn-reset').addEventListener('click', () => {
    svg.transition().duration(500).call(zoomBehavior.transform, d3.zoomIdentity);
    toast('تم إعادة ضبط العرض');
  });

  function fitView() {
    const bounds = container.node().getBBox();
    if (!bounds.width || !bounds.height) return;
    const vp = $('#tree-viewport');
    const w = vp.clientWidth;
    const h = vp.clientHeight;
    const mobile = isMobile();
    const pad = mobile ? 20 : 60;
    const maxScale = mobile ? 0.8 : 1.5;
    const scale = Math.min((w - pad * 2) / bounds.width, (h - pad * 2) / bounds.height, maxScale);
    const tx = (w - bounds.width * scale) / 2 - bounds.x * scale;
    const ty = (h - bounds.height * scale) / 2 - bounds.y * scale;
    svg.transition().duration(600)
      .call(zoomBehavior.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  }

  $('#btn-expand').addEventListener('click', () => {
    collapsed.clear();
    renderTree(true);
    toast('تم توسيع جميع الفروع');
    setTimeout(fitView, 600);
  });

  $('#btn-collapse').addEventListener('click', () => {
    allPersons.forEach(p => {
      if (p.children && p.children.length > 0) collapsed.add(p.id);
    });
    renderTree(true);
    toast('تم طي جميع الفروع');
    setTimeout(fitView, 600);
  });

  $('#btn-fullscreen').addEventListener('click', () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  });

  // ============================================
  // Keyboard
  // ============================================
  document.addEventListener('keydown', e => {
    if (e.key === '/') {
      e.preventDefault();
      if (isMobile() && mobileSearchBar) {
        mobileSearchBar.classList.remove('hidden');
        mobileSearchInput.focus();
      } else {
        searchInput.focus();
      }
    } else if (e.key === 'Escape') {
      closeModal();
      searchResults.classList.add('hidden');
      searchInput.blur();
      if (mobileSearchBar) mobileSearchBar.classList.add('hidden');
    } else if (e.key === '+' || e.key === '=') {
      svg.transition().duration(200).call(zoomBehavior.scaleBy, 1.2);
    } else if (e.key === '-') {
      svg.transition().duration(200).call(zoomBehavior.scaleBy, 0.83);
    } else if (e.key === 'f' || e.key === 'F') {
      if (document.activeElement === searchInput) return;
      fitView();
    } else if (e.key === 'ArrowLeft' && !$('#modal-overlay').classList.contains('hidden')) {
      navModal(1);
    } else if (e.key === 'ArrowRight' && !$('#modal-overlay').classList.contains('hidden')) {
      navModal(-1);
    }
  });

  // ============================================
  // Toast
  // ============================================
  function toast(msg) {
    const el = document.createElement('div');
    el.className = 'toast';
    el.textContent = msg;
    $('#toast-container').appendChild(el);
    setTimeout(() => el.remove(), 3000);
  }

  // ============================================
  // Spotlight: عبدالحافظ and descendants are bright, rest dimmed
  // ============================================
  function getDescendantIds(node) {
    const ids = new Set([node.id]);
    if (node.children) node.children.forEach(c => {
      getDescendantIds(c).forEach(id => ids.add(id));
    });
    return ids;
  }
  const spotlightRoot = findInTree(familyData, '12');
  const spotlightIds = spotlightRoot ? getDescendantIds(spotlightRoot) : new Set();
  spotlightIds.add('12');

  function applySpotlight() {
    nodeGroup.selectAll('.node-group').each(function(d) {
      const el = d3.select(this);
      const inSpot = spotlightIds.has(d.data.id);
      el.classed('dimmed', !inSpot);
      if (inSpot) {
        el.style('opacity', d.data._data.deceased ? 0.55 : 1)
          .style('filter', null);
      } else {
        el.style('opacity', 0.18)
          .style('filter', 'grayscale(1)');
      }
    });
    linkGroup.selectAll('.tree-link').each(function(d) {
      const el = d3.select(this);
      const inSpot = spotlightIds.has(d.source.data.id) && spotlightIds.has(d.target.data.id);
      el.classed('dimmed-link', !inSpot);
      el.style('opacity', inSpot ? null : 0.08);
    });
  }

  // ============================================
  // Init
  // ============================================
  function init() {
    if (darkMode) applyDarkMode();

    // Subtitle
    const total = allPersons.length;
    const gens = new Set(allPersons.map(p => p.depth)).size;
    $('#subtitle').textContent = `${total} فرد · ${gens} أجيال`;

    renderTree(true);

    // Apply spotlight on عبدالحافظ branch + fit view
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        applySpotlight();
        fitView();
      });
    });

    // Loading screen
    setTimeout(() => {
      const ls = $('#loading-screen');
      ls.classList.add('fade-out');
      setTimeout(() => ls.remove(), 500);
    }, 1000);

    // Re-fit on resize / orientation change
    let resizeTimer;
    const handleResize = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(fitView, 300);
    };
    window.addEventListener('resize', handleResize);
    window.addEventListener('orientationchange', () => setTimeout(fitView, 500));
  }

  // Start when D3 + DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  } // end initializeTree

})();
