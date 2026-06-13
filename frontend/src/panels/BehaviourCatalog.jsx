import { ListChecks } from "lucide-react";
import SectionTitle from "../components/ui/SectionTitle.jsx";
import Card from "../components/ui/Card.jsx";

/** Code-confirmed canonical behaviour tags. */
export default function BehaviourCatalog({ result }) {
  const catalog = result.behaviour_catalog || [];
  if (catalog.length === 0) return null;
  return (
    <section>
      <SectionTitle icon={ListChecks}>Behaviour Catalog — confirmed in code</SectionTitle>
      <Card className="p-4 flex flex-wrap gap-2">
        {catalog.map((t, i) => (
          <span
            key={i}
            className="rounded-md bg-boi-blue text-white px-2.5 py-1 text-xs font-600"
            style={{ fontWeight: 600 }}
          >
            {t}
          </span>
        ))}
      </Card>
    </section>
  );
}
