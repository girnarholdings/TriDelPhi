export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Inter&display=swap"
        />
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-TRAP" />
        <script
          dangerouslySetInnerHTML={{
            __html: "gtag('config', 'G-TRAP');",
          }}
        />
      </head>
      <body>
        <img src="/logo.png" />
        {children}
      </body>
    </html>
  );
}
