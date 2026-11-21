import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';
import { Inter } from 'next/font/google';
export const metadata = {
  title: { default: 'Signet', template: '%s | Signet' },
  description: 'Secure-by-default, embeddable authentication for Go.',
};


const inter = Inter({
  subsets: ['latin'],
});

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" className={inter.className} suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
