import { HostDetailClient } from "./host-detail-client";

export default async function HostDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <HostDetailClient hostId={id} />;
}
