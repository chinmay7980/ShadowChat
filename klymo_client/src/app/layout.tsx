import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ShadowChat | Private 1-to-1 Chat",
  description: "Anonymous, ephemeral, and safe chat platform.",
};

import SmoothScroll from "@/components/SmoothScroll";
import { UserProvider } from "@/context/UserContext";
import { AnimatedGridPattern } from "@/components/ui/animated-grid-pattern";
import { cn } from "@/lib/utils";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.className} min-h-screen selection:bg-green-500/30`}>
        <UserProvider>
          <SmoothScroll>
            <main className="relative min-h-screen">
              <AnimatedGridPattern
                numSquares={30}
                maxOpacity={0.1}
                duration={3}
                repeatDelay={1}
                className={cn(
                  "fixed inset-0 h-full w-full skew-y-12 opacity-50 z-0 pointer-events-none",
                )}
              />
              <div className="relative z-10">
                {children}
              </div>
            </main>
          </SmoothScroll>
        </UserProvider>
      </body>
    </html>
  );
}
