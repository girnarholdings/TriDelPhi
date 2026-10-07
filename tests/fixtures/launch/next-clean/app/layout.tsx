import { Inter } from "next/font/google";

const inter = Inter({ subsets: ["latin"] });

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.className}>
      <body>
        <nav>
          <a href="/">Home</a>
        </nav>
        <main>{children}</main>
        <footer>
          <a href="/privacy">Privacy</a>
          <a href="/terms">Terms</a>
          <a href="/dmca">DMCA</a>
        </footer>
      </body>
    </html>
  );
}
