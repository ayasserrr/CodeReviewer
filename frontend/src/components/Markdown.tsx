import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/** Renders agent-written markdown. Raw HTML is never rendered (no rehype-raw) — review text is untrusted. */
export function Markdown({ children }: { children: string }) {
  return (
    <div className="md">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>
    </div>
  );
}
