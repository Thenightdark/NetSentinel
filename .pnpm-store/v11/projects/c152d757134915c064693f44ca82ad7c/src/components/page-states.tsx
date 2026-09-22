export function LoadingState({ rows = 4 }: { rows?: number }) {
  return <div className="state-panel" aria-label="Loading data"><div className="skeleton skeleton-title" />{Array.from({ length: rows }, (_, index) => <div className="skeleton" key={index} />)}</div>;
}

export function ErrorState({ onRetry }: { onRetry: () => void }) {
  return <div className="state-panel state-message" role="alert"><span className="state-glyph">!</span><h2>Backend unavailable</h2><p>NetSentinel could not load this view. Confirm the FastAPI service is running and try again.</p><button className="button" onClick={onRetry}>Retry connection</button></div>;
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return <div className="empty"><span className="empty-rings" aria-hidden="true" /><h3>{title}</h3><p>{message}</p></div>;
}

