/* Builds the privacy report PDF entirely in the browser with jsPDF. Nothing is uploaded. */
(function () {
  const PW = 595.28, PH = 841.89, M = 40, CW = PW - M * 2, FOOT = 46;
  const LEVEL = { Critical: [248, 81, 73], High: [210, 153, 34], Medium: [47, 129, 247], Low: [139, 148, 158] };
  const INK = [22, 27, 34], MUTED = [101, 109, 118], BRAND = [47, 129, 247], DARK = [11, 18, 32], LINE = [216, 222, 228], ZEBRA = [246, 248, 250];

  // jsPDF's built-in fonts only cover Latin-1, so map or drop everything else.
  const t = s => String(s == null ? '' : s)
    .replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"').replace(/[\u2013\u2014\u2212]/g, '-').replace(/\u2026/g, '...').replace(/[\u2022\u00B7]/g, '-')
    .normalize('NFKD').replace(/[^\x20-\x7E\u00A0-\u00FF]/g, '').replace(/\s+/g, ' ').trim();

  window.buildReportPdf = function (r, logo) {
    const doc = new window.jspdf.jsPDF({ unit: 'pt', format: 'a4' });
    const when = new Date(r.generatedAt);
    const stamp = when.toLocaleString(undefined, { dateStyle: 'full', timeStyle: 'long' });
    const idText = t(r.identifier || r.subject);
    let y = 0;

    const fill = c => doc.setFillColor(c[0], c[1], c[2]);
    const ink = c => doc.setTextColor(c[0], c[1], c[2]);
    const draw = c => doc.setDrawColor(c[0], c[1], c[2]);
    const font = (size, style) => { doc.setFont('helvetica', style || 'normal'); doc.setFontSize(size); };
    const addLogo = (x, yy, h) => { if (logo) doc.addImage(logo.url, 'PNG', x, yy, h * logo.w / logo.h, h); };

    function smallHeader() {
      fill(DARK); doc.rect(0, 0, PW, 30, 'F');
      addLogo(M, 4, 22);
      font(10, 'bold'); ink([255, 255, 255]); doc.text('TRIVECTRA', M + 30, 19);
      font(8.5); ink([160, 174, 192]); doc.text(t('Digital Privacy Report - ' + idText), PW - M, 19, { align: 'right' });
    }
    function newPage() { doc.addPage(); smallHeader(); y = 48; }
    const ensure = h => { if (y + h > PH - FOOT) newPage(); };

    function para(str, { size = 10, style = 'normal', color = INK, x = M, w = CW, gap = 4 } = {}) {
      font(size, style); ink(color);
      const lh = size * 1.4;
      for (const line of doc.splitTextToSize(t(str), w)) { ensure(lh); doc.text(line, x, y + size); y += lh; }
      y += gap;
    }
    function heading(str) {
      ensure(40); y += 6; font(15, 'bold'); ink(INK); doc.text(t(str), M, y + 15);
      y += 22; draw(BRAND); doc.setLineWidth(1.5); doc.line(M, y, M + 44, y); draw(LINE); doc.setLineWidth(0.5); doc.line(M + 44, y, PW - M, y); y += 10;
    }
    function badge(str, x, yy, color) {
      font(8, 'bold'); const w = doc.getTextWidth(str) + 12;
      fill(color); doc.roundedRect(x, yy, w, 14, 3, 3, 'F'); ink([255, 255, 255]); doc.text(str, x + 6, yy + 10);
      return w;
    }
    function kvTable(rows, kw = 120) {
      const vw = CW - kw - 16;
      rows.forEach((row, i) => {
        font(9, 'bold'); const kl = doc.splitTextToSize(t(row.k), kw - 8);
        font(9); const vl = doc.splitTextToSize(t(row.v), vw);
        const h = Math.max(kl.length, vl.length) * 12.5 + 8;
        ensure(h);
        if (i % 2 === 0) { fill(ZEBRA); doc.rect(M, y, CW, h, 'F'); }
        font(9, 'bold'); ink(MUTED); doc.text(kl, M + 8, y + 15);
        font(9); ink(INK); doc.text(vl, M + kw + 8, y + 15);
        y += h;
      });
      y += 6;
    }
    function link(str, url, x, size, w) {
      font(size); ink(BRAND);
      const lines = doc.splitTextToSize(t(str), w);
      lines.forEach(l => { ensure(size * 1.4); doc.textWithLink(l, x, y + size, { url }); y += size * 1.4; });
    }

    /* ---- cover header ---- */
    fill(DARK); doc.rect(0, 0, PW, 118, 'F');
    fill(BRAND); doc.rect(0, 118, PW, 3, 'F');
    addLogo(M, 24, 70);
    const lx = M + (logo ? 70 * logo.w / logo.h : 0) + 16;
    font(26, 'bold'); ink([255, 255, 255]); doc.text('TRIVECTRA', lx, 58);
    font(12); ink([125, 211, 252]); doc.text('Digital Privacy Report', lx, 78);
    font(9); ink([160, 174, 192]); doc.text('Audit - Vault - Transfer', lx, 94);
    font(9); ink([226, 232, 240]); doc.text('Generated', PW - M, 44, { align: 'right' });
    font(9, 'bold'); doc.text(t(stamp), PW - M, 58, { align: 'right' });
    font(8.5); ink([160, 174, 192]); doc.text('UTC ' + r.generatedAt, PW - M, 72, { align: 'right' });
    y = 142;

    /* ---- subject + score ---- */
    const sc = r.score, scColor = sc >= 75 ? [63, 185, 80] : sc >= 45 ? [210, 153, 34] : [248, 81, 73];
    fill(ZEBRA); draw(LINE); doc.roundedRect(M, y, CW, 104, 6, 6, 'FD');
    font(9); ink(MUTED); doc.text('SUBJECT', M + 16, y + 20);
    font(13, 'bold'); ink(INK); doc.text(idText, M + 16, y + 38);
    font(9); ink(MUTED); doc.text(t(`Type: ${r.identifierType || 'identifier'}   -   ${r.summary.totalFindings} finding(s)`), M + 16, y + 54);
    font(9); doc.text(t('Potential score after remediation: ' + r.potentialScore + '/100'), M + 16, y + 94);
    fill(LINE); doc.roundedRect(M + 16, y + 68, 280, 10, 5, 5, 'F');
    fill(scColor); doc.roundedRect(M + 16, y + 68, Math.max(8, 280 * sc / 100), 10, 5, 5, 'F');
    font(40, 'bold'); ink(scColor); doc.text(String(sc), PW - M - 90, y + 58, { align: 'right' });
    font(12); ink(MUTED); doc.text('/100', PW - M - 86, y + 58);
    font(11, 'bold'); ink(scColor); doc.text(t(r.rating), PW - M - 16, y + 84, { align: 'right' });
    y += 120;

    /* ---- severity chips ---- */
    let cx = M;
    ['Critical', 'High', 'Medium', 'Low'].forEach(l => {
      const n = r.summary.byLevel[l] || 0;
      fill(n ? LEVEL[l] : LINE); doc.roundedRect(cx, y, 118, 40, 5, 5, 'F');
      font(18, 'bold'); ink(n ? [255, 255, 255] : MUTED); doc.text(String(n), cx + 12, y + 27);
      font(9); doc.text(l, cx + 40, y + 25); cx += 127;
    });
    y += 56;
    if (r.summary.dataTypesExposed.length) { para('Data types exposed: ' + r.summary.dataTypesExposed.join(', '), { size: 9.5, color: INK }); }

    /* ---- sources ---- */
    heading('Sources checked');
    kvTable((r.sourcesChecked || []).map(s => ({ k: s.name, v: s.ok ? `Reachable - ${s.hits} result(s)` : 'Unavailable - ' + (s.error || 'no response') })), 230);

    /* ---- findings ---- */
    heading('Findings and data found');
    if (!r.findings.length) para('No public exposure was found for this identifier.', { color: MUTED });
    r.findings.forEach((f, idx) => {
      const col = LEVEL[f.level] || LEVEL.Low;
      ensure(90); y += 4;
      fill(col); doc.rect(M, y, 4, 18, 'F');
      font(12, 'bold'); ink(INK); doc.text(t(`${idx + 1}. ${f.name}`), M + 12, y + 14);
      font(8, 'bold'); badge(f.level.toUpperCase() + '  -' + f.severity + ' pts', PW - M - (doc.getTextWidth(f.level.toUpperCase() + '  -' + f.severity + ' pts') + 12), y + 2, col);
      y += 24;
      para(`${f.type}  |  Source: ${f.source}  |  First seen: ${f.firstSeen}${f.reference ? '  |  Reference: ' + f.reference : ''}`, { size: 8.5, color: MUTED, gap: 3 });
      para(f.detail, { size: 10 });
      if (f.fields && f.fields.length) { para('DATA FOUND', { size: 8, style: 'bold', color: BRAND, gap: 2 }); kvTable(f.fields); }
      if (f.items && f.items.length) {
        para((f.id === 'footprint' ? 'PROFILES FOUND' : 'RECORDS') + ` (${f.items.length})`, { size: 8, style: 'bold', color: BRAND, gap: 2 });
        f.items.forEach(i => {
          const head = `${i.name}${i.date ? ' (' + i.date + ')' : ''}${i.records ? ' - ' + Number(i.records).toLocaleString() + ' records' : ''}`;
          ensure(30); para(head, { size: 9.5, style: 'bold', gap: 0, x: M + 8, w: CW - 8 });
          if (i.url && /^https?:\/\//.test(i.url)) link(i.url, i.url, M + 8, 8.5, CW - 8);
          const info = i.info || {};
          if (info.title && info.title !== i.name) para(info.title, { size: 8.5, color: INK, gap: 0, x: M + 8, w: CW - 8 });
          if (info.description) para(info.description, { size: 8.5, color: MUTED, gap: 0, x: M + 8, w: CW - 8 });
          if (i.data && !/^https?:\/\//.test(i.data)) para('Data exposed: ' + i.data, { size: 8.5, color: MUTED, gap: 0, x: M + 8, w: CW - 8 });
          y += 5;
        });
      }
      para('Data types exposed: ' + f.exposed.join(', '), { size: 9, color: MUTED, gap: 2 });
      para('Risk: ' + f.risk, { size: 9, color: MUTED, gap: 4 });
      para(`How to remove it (effort ${f.effort}, about ${f.time}):`, { size: 9.5, style: 'bold', gap: 2 });
      f.steps.forEach((s, n) => para(`${n + 1}. ${s}`, { size: 9.5, x: M + 8, w: CW - 8, gap: 1 }));
      if (f.url && /^https:\/\//.test(f.url)) { y += 3; link('Source: ' + f.url, f.url, M, 8.5, CW); }
      y += 12; draw(LINE); doc.line(M, y - 6, PW - M, y - 6);
    });

    /* ---- manual checks ---- */
    if (r.manualChecks && r.manualChecks.length) {
      heading('Manual checks (login required)');
      para('These platforms cannot be checked automatically without signing in. Open each link to verify whether the account exists.', { size: 9.5, color: MUTED });
      r.manualChecks.forEach(m => { link(`${m.name}: ${m.url}`, m.url, M + 8, 9, CW - 8); });
      y += 6;
    }

    /* ---- action plan ---- */
    if (r.actionPlan.length) {
      heading('Prioritised action plan');
      para('Ordered by score recovered per unit of effort.', { size: 9, color: MUTED });
      kvTable(r.actionPlan.map(p => ({ k: `${p.priority}. ${p.source}`, v: `Effort ${p.effort}, about ${p.estimatedTime}, recovers +${p.pointsRecovered} points` })), 230);
    }
    heading('General recommendations');
    r.general.forEach(g => para('- ' + g, { size: 10, gap: 2 }));
    y += 6;
    para(r.note, { size: 8.5, style: 'italic', color: MUTED });

    /* ---- footer on every page ---- */
    const pages = doc.getNumberOfPages();
    for (let p = 1; p <= pages; p++) {
      doc.setPage(p); draw(LINE); doc.setLineWidth(0.5); doc.line(M, PH - 32, PW - M, PH - 32);
      font(8); ink(MUTED);
      doc.text(t(`Trivectra - Generated ${stamp}`), M, PH - 20);
      doc.text(`Page ${p} of ${pages}`, PW - M, PH - 20, { align: 'right' });
    }
    return doc;
  };
})();
