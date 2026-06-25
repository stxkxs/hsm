import { Construction } from "lucide-react";
import { Header } from "@/components/layout/header";
import { PageContainer } from "@/components/layout/page-container";
import { Card, CardContent } from "@/components/ui/card";

interface ComingSoonProps {
  title: string;
  description?: string;
  detail?: string;
}

/**
 * Placeholder for sections whose backend is not yet wired into the HSM server.
 *
 * Shown instead of a real-looking page that would call REST routes the server
 * does not register, so the console never presents an unimplemented feature as
 * if it worked.
 */
export function ComingSoon({ title, description, detail }: ComingSoonProps) {
  return (
    <>
      <Header title={title} description={description} />
      <PageContainer>
        <Card className="animate-fade-in-up">
          <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
              <Construction className="h-6 w-6 text-primary" />
            </div>
            <p className="text-sm font-medium">Not yet available</p>
            <p className="max-w-md text-xs text-muted-foreground">
              {detail ??
                "This section is not wired to the HSM backend yet. It will be enabled in a future release."}
            </p>
          </CardContent>
        </Card>
      </PageContainer>
    </>
  );
}
