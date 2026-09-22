import { useState } from "react";
import { useCanvasStore } from "../store/useCanvasStore";

export default function ChatPanel() {
  const chatOpen = useCanvasStore((s) => s.chatOpen);
  const chatMessages = useCanvasStore((s) => s.chatMessages);
  const chatLoading = useCanvasStore((s) => s.chatLoading);
  const chatError = useCanvasStore((s) => s.chatError);
  const sendChatMessage = useCanvasStore((s) => s.sendChatMessage);
  const [draft, setDraft] = useState("");

  if (!chatOpen) return null;

  const submit = () => {
    const text = draft.trim();
    if (!text || chatLoading) return;
    setDraft("");
    sendChatMessage(text);
  };

  return (
    <div className="ai-chat-panel">
      <div className="ai-chat-panel__header">
        <span>Describe your deployment</span>
      </div>

      <div className="ai-chat-panel__messages">
        {chatMessages.length === 0 && (
          <p className="ai-chat-panel__empty">
            Describe your organisation, departments, actors, and AI
            deployment in plain language — e.g. "We have a Data Science team
            that trains a clinical triage LLM, and a Compliance team that
            validates it. We need a DPIA." New elements land on the canvas
            for you to review and refine.
          </p>
        )}
        {chatMessages.map((m, i) => (
          <div
            key={i}
            className={`ai-chat-msg ai-chat-msg--${m.role === "user" ? "user" : "assistant"}`}
          >
            {m.content}
          </div>
        ))}
        {chatLoading && (
          <div className="ai-chat-msg ai-chat-msg--assistant ai-chat-msg--pending">
            Thinking…
          </div>
        )}
        {chatError && <div className="ai-chat-msg ai-chat-msg--error">{chatError}</div>}
      </div>

      <div className="ai-chat-panel__composer">
        <textarea
          rows={2}
          value={draft}
          placeholder="e.g. We have a Trainer and Validator in Data Science…"
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
            }
          }}
        />
        <button type="button" onClick={submit} disabled={chatLoading || !draft.trim()}>
          Send
        </button>
      </div>
    </div>
  );
}
