import { ScanView } from "@/components/ScanView";

export const dynamic = "force-dynamic";

export default function ScanPage({ params }: { params: { id: string } }) {
  return <ScanView scanId={params.id} />;
}
