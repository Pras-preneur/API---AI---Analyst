import React from 'react';

interface MarkdownRendererProps {
  content: string;
  className?: string;
}

/**
 * Lightweight, zero-dependency markdown renderer for chat messages.
 * Handles: headings (#, ##, ###, ####), **bold**, *italic*, `inline code`,
 * ```fenced code blocks```, - bullet lists, 1. numbered lists, > blockquote, ---.
 */
export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content, className = '' }) => {
  const rendered = parseMarkdown(content);
  return (
    <div
      className={`chat-prose text-sm ${className}`}
      dangerouslySetInnerHTML={{ __html: rendered }}
    />
  );
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseInline(text: string): string {
  // Process inline: code first (prevents inner markdown processing inside code)
  return text
    // Inline code  `code`
    .replace(/`([^`\n]+)`/g, (_, c) => `<code>${escapeHtml(c)}</code>`)
    // Bold **text** or __text__
    .replace(/\*\*(.+?)\*\*/g, (_, c) => `<strong>${c}</strong>`)
    .replace(/__(.+?)__/g, (_, c) => `<strong>${c}</strong>`)
    // Italic *text* or _text_
    .replace(/\*([^*\n]+)\*/g, (_, c) => `<em>${c}</em>`)
    .replace(/_([^_\n]+)_/g, (_, c) => `<em>${c}</em>`);
}

function parseMarkdown(markdown: string): string {
  const lines = markdown.split('\n');
  const html: string[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // ── Fenced code block ───────────────────────────────────────────────────
    if (line.trimStart().startsWith('```')) {
      const lang = line.trim().slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith('```')) {
        codeLines.push(escapeHtml(lines[i]));
        i++;
      }
      i++; // skip closing ```
      html.push(`<pre><code class="language-${escapeHtml(lang)}">${codeLines.join('\n')}</code></pre>`);
      continue;
    }

    // ── Headings ─────────────────────────────────────────────────────────────
    const heading = line.match(/^(#{1,4})\s+(.*)/);
    if (heading) {
      const level = heading[1].length;
      html.push(`<h${level}>${parseInline(heading[2])}</h${level}>`);
      i++;
      continue;
    }

    // ── Horizontal rule ──────────────────────────────────────────────────────
    if (/^(\s*[-*_]){3,}\s*$/.test(line)) {
      html.push('<hr />');
      i++;
      continue;
    }

    // ── Blockquote ───────────────────────────────────────────────────────────
    if (line.startsWith('> ')) {
      const quoteLines: string[] = [];
      while (i < lines.length && lines[i].startsWith('> ')) {
        quoteLines.push(parseInline(lines[i].slice(2)));
        i++;
      }
      html.push(`<blockquote>${quoteLines.join('<br />')}</blockquote>`);
      continue;
    }

    // ── Unordered list ───────────────────────────────────────────────────────
    if (/^(\s*[-*+])\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^(\s*[-*+])\s+/.test(lines[i])) {
        items.push(`<li>${parseInline(lines[i].replace(/^(\s*[-*+])\s+/, ''))}</li>`);
        i++;
      }
      html.push(`<ul>${items.join('')}</ul>`);
      continue;
    }

    // ── Ordered list ─────────────────────────────────────────────────────────
    if (/^\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\d+\.\s+/.test(lines[i])) {
        items.push(`<li>${parseInline(lines[i].replace(/^\d+\.\s+/, ''))}</li>`);
        i++;
      }
      html.push(`<ol>${items.join('')}</ol>`);
      continue;
    }

    // ── Empty line ───────────────────────────────────────────────────────────
    if (line.trim() === '') {
      i++;
      continue;
    }

    // ── Paragraph ────────────────────────────────────────────────────────────
    const paraLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== '' &&
      !lines[i].startsWith('#') &&
      !lines[i].startsWith('```') &&
      !lines[i].startsWith('> ') &&
      !/^(\s*[-*+])\s+/.test(lines[i]) &&
      !/^\d+\.\s+/.test(lines[i]) &&
      !/^(\s*[-*_]){3,}\s*$/.test(lines[i])
    ) {
      paraLines.push(parseInline(lines[i]));
      i++;
    }
    if (paraLines.length > 0) {
      html.push(`<p>${paraLines.join('<br />')}</p>`);
    }
  }

  return html.join('\n');
}
