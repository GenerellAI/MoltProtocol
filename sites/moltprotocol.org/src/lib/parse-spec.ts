/**
 * Shared markdown-to-HTML converter and ToC extractor for spec pages.
 * Runs at build time in Astro frontmatter.
 */

export interface TocEntry {
  id: string;
  text: string;
  level: number;
}

function makeId(text: string): string {
  // Strip HTML tags and inline code markup
  const clean = text.replace(/<[^>]+>/g, '').replace(/`([^`]+)`/g, '$1');
  return clean
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

const LINK_ICON = `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M7.775 3.275a.75.75 0 001.06 1.06l1.25-1.25a2 2 0 112.83 2.83l-2.5 2.5a2 2 0 01-2.83 0 .75.75 0 00-1.06 1.06 3.5 3.5 0 004.95 0l2.5-2.5a3.5 3.5 0 00-4.95-4.95l-1.25 1.25zm-.025 9.45a.75.75 0 01-1.06-1.06l-1.25 1.25a2 2 0 01-2.83-2.83l2.5-2.5a2 2 0 012.83 0 .75.75 0 001.06-1.06 3.5 3.5 0 00-4.95 0l-2.5 2.5a3.5 3.5 0 004.95 4.95l1.25-1.25z"/></svg>`;

export function parseSpec(md: string): { html: string; toc: TocEntry[] } {
  const toc: TocEntry[] = [];

  // Strip YAML frontmatter if present
  let content = md.replace(/^---[\s\S]*?---\s*/, '');

  let html = content;

  // Code blocks (fenced) — must come first to protect content inside
  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_m, lang, code) => {
    const escaped = code
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
    return `<pre><code class="language-${lang || 'text'}">${escaped}</code></pre>`;
  });

  // Tables
  html = html.replace(
    /^(\|.+\|)\n(\|[\s\-:|]+\|)\n((?:\|.+\|\n?)*)/gm,
    (_m, header, _sep, body) => {
      const headers = header
        .split('|')
        .filter((c: string) => c.trim())
        .map((c: string) => `<th>${c.trim()}</th>`)
        .join('');
      const rows = body
        .trim()
        .split('\n')
        .map((row: string) => {
          const cells = row
            .split('|')
            .filter((c: string) => c.trim())
            .map((c: string) => `<td>${c.trim()}</td>`)
            .join('');
          return `<tr>${cells}</tr>`;
        })
        .join('\n');
      return `<table><thead><tr>${headers}</tr></thead><tbody>${rows}</tbody></table>`;
    },
  );

  // Inline code (before other inline processing)
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Headers — add IDs to h2, h3, h4 and collect ToC
  html = html.replace(/^(#{2,4}) (.+)$/gm, (_m, hashes, text) => {
    const level = hashes.length as 2 | 3 | 4;
    const tag = `h${level}`;
    const id = makeId(text);
    const anchor = `<a href="#${id}" class="heading-anchor" aria-label="Link to this section">${LINK_ICON}</a>`;

    // Collect h2 and h3 for the ToC (skip h4 to keep it manageable)
    if (level <= 3) {
      // Strip any HTML from text for clean ToC display
      const cleanText = text.replace(/<[^>]+>/g, '').replace(/`([^`]+)`/g, '$1');
      toc.push({ id, text: cleanText, level });
    }

    return `<${tag} id="${id}">${text}${anchor}</${tag}>`;
  });

  // h1 — no ID, no anchor, no ToC entry
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

  // Bold + italic
  html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

  // Links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

  // Blockquotes
  html = html.replace(/^> (.+)$/gm, '<blockquote><p>$1</p></blockquote>');

  // Horizontal rules
  html = html.replace(/^---$/gm, '<hr>');

  // Unordered lists (simple, single-level)
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
  html = html.replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul>$1</ul>');

  // Ordered lists
  html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

  // Paragraphs (lines not already wrapped in HTML)
  const lines = html.split('\n');
  const result: string[] = [];
  let inPre = false;
  for (const line of lines) {
    if (line.includes('<pre>')) inPre = true;
    if (line.includes('</pre>')) {
      inPre = false;
      result.push(line);
      continue;
    }
    if (inPre) {
      result.push(line);
      continue;
    }
    if (line.trim() === '') {
      result.push('');
      continue;
    }
    if (
      /^<(h[1-6]|ul|ol|li|table|thead|tbody|tr|th|td|pre|blockquote|hr|div|p)/.test(
        line.trim(),
      )
    ) {
      result.push(line);
    } else if (line.trim()) {
      result.push(`<p>${line}</p>`);
    }
  }

  return { html: result.join('\n'), toc };
}
